"""위험 점수: DB 함수와 Python 함수의 일치, 판정 변경 시 재산정, 위험 요약."""

import itertools
import json
import uuid
from dataclasses import dataclass
from decimal import Decimal

import psycopg
import pytest
from psycopg import errors

from modules.compliance.risk_evaluator import ItemStatus, RiskLevel, RiskPolicy, risk_score
from tests.db.helpers import _auth_user, _count, _member, _new_id, _one, as_role, expect_error

REASON = "대체 통제(방화벽 차단) 적용으로 예외 승인"
STATUSES: list[ItemStatus] = ["good", "vulnerable", "na"]
LEVELS: list[RiskLevel] = ["high", "medium", "low"]
SCORES = [1, 2, 3]
WEIGHTS = [Decimal("1.00"), Decimal("1.50")]


def test_python_and_sql_formulas_agree_for_every_combination(db: psycopg.Connection) -> None:
    for status, level, c, i, a, weight in itertools.product(
        STATUSES, LEVELS, SCORES, SCORES, SCORES, WEIGHTS
    ):
        sql = _one(
            db,
            "select private.compute_risk_score(%s, %s, %s, %s, %s, %s, 1.00, 1.00)",
            (status, level, c, i, a, weight),
        )
        python = risk_score(status, level, c, i, a, RiskPolicy(confidentiality_weight=weight))
        assert Decimal(str(sql)) == python, (status, level, c, i, a, weight)


@dataclass(frozen=True)
class Scored:
    tenant: uuid.UUID
    run: uuid.UUID
    result: uuid.UUID
    operator: uuid.UUID
    viewer: uuid.UUID
    outsider: uuid.UUID


@pytest.fixture
def scored(db: psycopg.Connection) -> Scored:
    """CIA 3·3·3 자산의 '상' 등급 취약 항목(27점) 하나와, 점수가 다른 취약 항목 몇 개."""
    tenant = _new_id(db, "insert into tenants (name) values ('보안팀') returning id")
    db.execute("insert into risk_scoring_policies (tenant_id) values (%s)", (tenant,))
    asset = _new_id(
        db,
        "insert into assets (tenant_id, hostname, os_type, confidentiality_score, integrity_score, "
        "availability_score) values (%s, 'db-01', 'linux', 3, 3, 3) returning id",
        (tenant,),
    )
    run = _new_id(
        db,
        "insert into assessment_runs (tenant_id, title, status) values (%s, '진단', 'completed') "
        "returning id",
        (tenant,),
    )
    rows = [
        ("U-01", "vulnerable", 27),
        ("U-15", "vulnerable", 14),
        ("U-16", "vulnerable", 7),
        ("U-18", "good", 0),
    ]
    ids = {}
    for code, status, score in rows:
        ids[code] = _new_id(
            db,
            "insert into inspection_item_results (tenant_id, assessment_run_id, asset_id, "
            "item_code, auto_status, final_status, calculated_risk_score) "
            "values (%s, %s, %s, %s, %s, %s, %s) "
            "returning id",
            (tenant, run, asset, code, status, status, score),
        )
    db.execute("update assessment_runs set vulnerable_items_count = 3 where id = %s", (run,))
    other = _new_id(db, "insert into tenants (name) values ('다른 회사') returning id")
    return Scored(
        tenant=tenant,
        run=run,
        result=ids["U-01"],
        operator=_member(db, tenant, "operator"),
        viewer=_member(db, tenant, "viewer"),
        outsider=_member(db, other, "owner"),
    )


def _override(
    db: psycopg.Connection, run: uuid.UUID, result: uuid.UUID, status: str, reason: str
) -> dict[str, object]:
    value = _one(
        db, "select public.apply_item_override(%s, %s, %s, %s)", (run, result, status, reason)
    )
    assert isinstance(value, dict)
    return value


def test_override_to_good_zeroes_score_and_syncs_count(
    db: psycopg.Connection, scored: Scored
) -> None:
    with as_role(db, "authenticated", scored.operator):
        result = _override(db, scored.run, scored.result, "good", REASON)
    assert result["final_status"] == "good"
    assert Decimal(str(result["calculated_risk_score"])) == 0
    assert result["changed"] is True
    assert result["vulnerable_items_count"] == 2
    assert (
        _one(db, "select vulnerable_items_count from assessment_runs where id = %s", (scored.run,))
        == 2
    )
    audit = db.execute(
        "select previous_status::text, new_status::text, override_reason from override_audit_logs "
        "where inspection_item_result_id = %s",
        (scored.result,),
    ).fetchall()
    assert audit == [("vulnerable", "good", REASON)]


def test_override_back_to_vulnerable_recomputes_27(db: psycopg.Connection, scored: Scored) -> None:
    with as_role(db, "authenticated", scored.operator):
        _override(db, scored.run, scored.result, "good", REASON)
        result = _override(
            db, scored.run, scored.result, "vulnerable", "재점검 결과 다시 취약으로 확인"
        )
    assert Decimal(str(result["calculated_risk_score"])) == Decimal("27.00")
    assert result["vulnerable_items_count"] == 3
    assert (
        _count(
            db, "select count(*) from override_audit_logs where tenant_id = %s", (scored.tenant,)
        )
        == 2
    )


def test_same_status_is_idempotent(db: psycopg.Connection, scored: Scored) -> None:
    with as_role(db, "authenticated", scored.operator):
        result = _override(db, scored.run, scored.result, "vulnerable", REASON)
    assert (result["changed"], result["audit_id"]) == (False, None)
    assert (
        _count(
            db, "select count(*) from override_audit_logs where tenant_id = %s", (scored.tenant,)
        )
        == 0
    )


def test_item_must_belong_to_the_given_run(db: psycopg.Connection, scored: Scored) -> None:
    with (
        as_role(db, "authenticated", scored.operator),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        _override(db, uuid.uuid4(), scored.result, "good", REASON)


@pytest.mark.parametrize("reason", ["", "    ", "짧음", "x" * 1001])
def test_reason_length_is_enforced(db: psycopg.Connection, scored: Scored, reason: str) -> None:
    with (
        as_role(db, "authenticated", scored.operator),
        expect_error(db, errors.InvalidParameterValue),
    ):
        _override(db, scored.run, scored.result, "good", reason)


@pytest.mark.parametrize("actor", ["viewer", "outsider"])
def test_viewer_and_other_tenant_cannot_override(
    db: psycopg.Connection, scored: Scored, actor: str
) -> None:
    with (
        as_role(db, "authenticated", getattr(scored, actor)),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        _override(db, scored.run, scored.result, "good", REASON)


SUMMARY = "select * from public.get_assessment_risk_summary(%s)"


def test_risk_summary_counts_categories(db: psycopg.Connection, scored: Scored) -> None:
    with as_role(db, "authenticated", scored.viewer):
        row = db.execute(SUMMARY, (scored.run,)).fetchone()
    # 27 → 긴급, 14 → 경고, 7 → 주의
    assert row == (3, 1, 1, 1, Decimal("27.00"), 15, 8)


def test_risk_summary_uses_tenant_thresholds(db: psycopg.Connection, scored: Scored) -> None:
    db.execute(
        "update risk_scoring_policies set critical_threshold = 28, warning_threshold = 14 "
        "where tenant_id = %s",
        (scored.tenant,),
    )
    with as_role(db, "authenticated", scored.viewer):
        row = db.execute(SUMMARY, (scored.run,)).fetchone()
    assert row is not None
    assert row[1:4] == (0, 2, 1)


def test_risk_summary_hidden_from_others(db: psycopg.Connection, scored: Scored) -> None:
    for who in (scored.outsider, _auth_user(db)):
        with as_role(db, "authenticated", who):
            assert db.execute(SUMMARY, (scored.run,)).fetchall() == []
    with as_role(db, "anon"), expect_error(db, errors.InsufficientPrivilege):
        db.execute(SUMMARY, (scored.run,))


def test_audit_payload_is_json_serialisable(db: psycopg.Connection, scored: Scored) -> None:
    with as_role(db, "authenticated", scored.operator):
        result = _override(db, scored.run, scored.result, "na", REASON)
    assert json.loads(json.dumps(result))["final_status"] == "na"

"""자산 중요도·위험도 정책 변경 시 점수 재계산, 자산 개요·대시보드 집계."""

import uuid
from dataclasses import dataclass
from decimal import Decimal

import psycopg
import pytest
from psycopg import errors

from tests.db.helpers import _member, _new_id, _one, as_role, expect_error

IMPORTANCE = "select public.update_asset_importance(%s, %s, %s, %s)"
POLICY = "select public.save_risk_policy(%s, %s::numeric, %s::numeric, %s::numeric, %s, %s)"


@dataclass(frozen=True)
class Ws:
    tenant: uuid.UUID
    run: uuid.UUID
    asset: uuid.UUID
    other_asset: uuid.UUID
    owner: uuid.UUID
    operator: uuid.UUID
    viewer: uuid.UUID
    outsider: uuid.UUID


@pytest.fixture
def ws(db: psycopg.Connection) -> Ws:
    """자산 2개(3·3·3, 1·1·1), '상' 취약 항목(U-01)·'중' 취약 항목(U-08)·양호 항목(U-02)."""
    tenant = _new_id(db, "insert into tenants (name) values ('보안팀') returning id")
    asset = _new_id(
        db,
        "insert into assets (tenant_id, hostname, os_type, confidentiality_score, integrity_score, "
        "availability_score) values (%s, 'db-01', 'linux', 3, 3, 3) returning id",
        (tenant,),
    )
    other = _new_id(
        db,
        "insert into assets (tenant_id, hostname, os_type, confidentiality_score, integrity_score, "
        "availability_score) values (%s, 'web-01', 'linux', 1, 1, 1) returning id",
        (tenant,),
    )
    run = _new_id(
        db,
        "insert into assessment_runs (tenant_id, title, status) values (%s, '정기 진단', "
        "'completed') returning id",
        (tenant,),
    )
    for asset_id, code, status, score in (
        (asset, "U-01", "vulnerable", 27),
        (asset, "U-08", "vulnerable", 18),
        (asset, "U-02", "good", 0),
        (other, "U-01", "vulnerable", 9),
    ):
        db.execute(
            "insert into inspection_item_results (tenant_id, assessment_run_id, asset_id, "
            "item_code, auto_status, final_status, calculated_risk_score) "
            "values (%s, %s, %s, %s, %s, %s, %s)",
            (tenant, run, asset_id, code, status, status, score),
        )
    other_tenant = _new_id(db, "insert into tenants (name) values ('다른 회사') returning id")
    return Ws(
        tenant=tenant,
        run=run,
        asset=asset,
        other_asset=other,
        owner=_member(db, tenant, "owner"),
        operator=_member(db, tenant, "operator"),
        viewer=_member(db, tenant, "viewer"),
        outsider=_member(db, other_tenant, "owner"),
    )


def scores(db: psycopg.Connection, asset: uuid.UUID) -> dict[str, Decimal]:
    rows = db.execute(
        "select item_code, calculated_risk_score from inspection_item_results where asset_id = %s",
        (asset,),
    ).fetchall()
    return {code: Decimal(score) for code, score in rows}


def test_operator_changes_importance_and_scores_follow(db: psycopg.Connection, ws: Ws) -> None:
    with as_role(db, "authenticated", ws.operator):
        result = _one(db, IMPORTANCE, (ws.asset, 1, 2, 1))
    assert isinstance(result, dict) and result["recalculated_items"] == 3
    # 중요도 4 × 상 3 = 12, × 중 2 = 8, 양호 0
    assert scores(db, ws.asset) == {
        "U-01": Decimal("12.00"),
        "U-08": Decimal("8.00"),
        "U-02": Decimal("0.00"),
    }
    assert scores(db, ws.other_asset) == {"U-01": Decimal("9.00")}  # 다른 자산은 그대로


@pytest.mark.parametrize("actor", ["viewer", "outsider"])
def test_viewer_and_outsider_cannot_change_importance(
    db: psycopg.Connection, ws: Ws, actor: str
) -> None:
    with (
        as_role(db, "authenticated", getattr(ws, actor)),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        _one(db, IMPORTANCE, (ws.asset, 1, 1, 1))


@pytest.mark.parametrize("values", [(0, 1, 1), (1, 4, 1), (1, 1, None)])
def test_importance_range(db: psycopg.Connection, ws: Ws, values: tuple[int, int, int]) -> None:
    with (
        as_role(db, "authenticated", ws.operator),
        expect_error(db, errors.InvalidParameterValue),
    ):
        _one(db, IMPORTANCE, (ws.asset, *values))


def test_owner_saves_policy_and_all_scores_follow(db: psycopg.Connection, ws: Ws) -> None:
    with as_role(db, "authenticated", ws.owner):
        result = _one(db, POLICY, (ws.tenant, 2, 1, 1, 30, 12))
        again = _one(db, POLICY, (ws.tenant, 2, 1, 1, 30, 12))  # 갱신도 가능
    assert isinstance(result, dict) and result["recalculated_items"] == 4
    assert isinstance(again, dict)
    # (3×2 + 3 + 3) × 3 = 36, × 2 = 24 / web-01: (1×2+1+1) × 3 = 12
    assert scores(db, ws.asset)["U-01"] == Decimal("36.00")
    assert scores(db, ws.asset)["U-08"] == Decimal("24.00")
    assert scores(db, ws.other_asset)["U-01"] == Decimal("12.00")
    row = db.execute(
        "select confidentiality_weight, critical_threshold, warning_threshold "
        "from risk_scoring_policies where tenant_id = %s",
        (ws.tenant,),
    ).fetchone()
    assert row == (Decimal("2.00"), 30, 12)


@pytest.mark.parametrize("actor", ["operator", "viewer", "outsider"])
def test_only_owner_saves_policy(db: psycopg.Connection, ws: Ws, actor: str) -> None:
    with (
        as_role(db, "authenticated", getattr(ws, actor)),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        _one(db, POLICY, (ws.tenant, 1, 1, 1, 15, 8))


@pytest.mark.parametrize(
    "values",
    [(0.4, 1, 1, 15, 8), (1, 3.1, 1, 15, 8), (1, 1, 1, 8, 8), (1, 1, 1, 15, 0), (1, 1, 1, 82, 8)],
)
def test_policy_validation(
    db: psycopg.Connection, ws: Ws, values: tuple[float, float, float, int, int]
) -> None:
    with (
        as_role(db, "authenticated", ws.owner),
        expect_error(db, errors.InvalidParameterValue),
    ):
        _one(db, POLICY, (ws.tenant, *values))


def test_policy_not_directly_writable(db: psycopg.Connection, ws: Ws) -> None:
    with (
        as_role(db, "authenticated", ws.owner),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        db.execute("insert into risk_scoring_policies (tenant_id) values (%s)", (ws.tenant,))


def test_asset_overview(db: psycopg.Connection, ws: Ws) -> None:
    query = (
        "select hostname, checks, vulnerable, critical, max_risk_score from get_asset_overview(%s)"
    )
    with as_role(db, "authenticated", ws.viewer):
        rows = db.execute(query, (ws.tenant,)).fetchall()
    assert rows == [
        ("db-01", 3, 2, 2, Decimal("27.00")),  # 27·18 모두 긴급(15 이상)
        ("web-01", 1, 1, 0, Decimal("9.00")),
    ]
    with as_role(db, "authenticated", ws.outsider):
        assert db.execute(query, (ws.tenant,)).fetchall() == []


def test_dashboard_summary(db: psycopg.Connection, ws: Ws) -> None:
    with as_role(db, "authenticated", ws.viewer):
        summary = _one(db, "select get_dashboard_summary(%s)", (ws.tenant,))
    assert isinstance(summary, dict)
    assert (summary["asset_count"], summary["run_count"]) == (2, 1)
    latest = summary["latest"]
    assert isinstance(latest, dict)
    assert (latest["checks"], latest["good"], latest["vulnerable"]) == (4, 1, 3)
    assert (latest["critical"], latest["warning"], latest["caution"]) == (2, 1, 0)
    top = summary["top_assets"]
    assert isinstance(top, list)
    assert [t["hostname"] for t in top] == ["db-01", "web-01"]
    assert len(summary["trend"]) == 1
    categories = {c["category"]: c["vulnerable"] for c in summary["categories"]}
    assert categories == {"account_management": 3}


def test_dashboard_hidden_from_others(db: psycopg.Connection, ws: Ws) -> None:
    with as_role(db, "authenticated", ws.outsider):
        summary = _one(db, "select get_dashboard_summary(%s)", (ws.tenant,))
    assert isinstance(summary, dict)
    assert (summary["asset_count"], summary["run_count"], summary["latest"]) == (0, 0, None)
    assert summary["top_assets"] == [] and summary["trend"] == []

"""진단 인프라 데이터 기반 검증.

스키마, KISA 시드, 수동 판정 변경, 감사 불변성, 테넌트 격리(RLS).
"""

import uuid
from dataclasses import dataclass

import psycopg
import pytest
from psycopg import errors

from tests.db.helpers import _auth_user, _count, _member, _new_id, _one, as_role, expect_error

CORE_TABLES = {
    "tenants",
    "users",
    "invitations",
    "assets",
    "assessment_runs",
    "diagnostic_logs",
    "compliance_guidelines",
    "inspection_item_results",
    "override_audit_logs",
    "risk_scoring_policies",
    "generated_reports",
}
REASON = "방화벽 접근 제어로 보안 위협 해소됨"


@dataclass(frozen=True)
class Sample:
    tenant_a: uuid.UUID
    tenant_b: uuid.UUID
    owner_a: uuid.UUID  # auth.users id
    operator_a: uuid.UUID
    viewer_a: uuid.UUID
    suspended_a: uuid.UUID
    owner_b: uuid.UUID
    asset_a: uuid.UUID
    asset_b: uuid.UUID
    run_a: uuid.UUID
    run_b: uuid.UUID
    result_a: uuid.UUID


INSERT_TENANT = "insert into tenants (name) values (%s) returning id"
INSERT_ASSET = (
    "insert into assets (tenant_id, hostname, os_type, confidentiality_score, integrity_score, "
    "availability_score) values (%s, %s, 'linux', 2, 3, 2) returning id"
)
INSERT_RUN = (
    "insert into assessment_runs (tenant_id, title) values (%s, '2026 상반기 진단') returning id"
)
INSERT_RESULT = (
    "insert into inspection_item_results (tenant_id, assessment_run_id, asset_id, item_code, "
    "auto_status, final_status, stdout_snippet, raw_log_start_line, raw_log_end_line) "
    "values (%s, %s, %s, 'U-01', 'vulnerable', 'vulnerable', 'PermitRootLogin yes', 10, 12) "
    "returning id"
)


@pytest.fixture
def sample(db: psycopg.Connection) -> Sample:
    tenant_a = _new_id(db, INSERT_TENANT, ("테넌트 A",))
    tenant_b = _new_id(db, INSERT_TENANT, ("테넌트 B",))
    asset_a = _new_id(db, INSERT_ASSET, (tenant_a, "web-01"))
    asset_b = _new_id(db, INSERT_ASSET, (tenant_b, "db-01"))
    run_a = _new_id(db, INSERT_RUN, (tenant_a,))
    run_b = _new_id(db, INSERT_RUN, (tenant_b,))
    return Sample(
        tenant_a=tenant_a,
        tenant_b=tenant_b,
        owner_a=_member(db, tenant_a, "owner"),
        operator_a=_member(db, tenant_a, "operator"),
        viewer_a=_member(db, tenant_a, "viewer"),
        suspended_a=_member(db, tenant_a, "operator", status="suspended"),
        owner_b=_member(db, tenant_b, "owner"),
        asset_a=asset_a,
        asset_b=asset_b,
        run_a=run_a,
        run_b=run_b,
        result_a=_new_id(db, INSERT_RESULT, (tenant_a, run_a, asset_a)),
    )


def _override(conn: psycopg.Connection, result: uuid.UUID, status: str, reason: str | None) -> None:
    conn.execute(
        "select public.apply_item_override("
        "(select assessment_run_id from inspection_item_results where id = %s), %s, %s, %s)",
        (result, result, status, reason),
    )


# --- 스키마 · 시드 -----------------------------------------------------------------------


def test_core_tables_exist_with_rls_enabled(db: psycopg.Connection) -> None:
    rows = db.execute(
        "select c.relname, c.relrowsecurity from pg_class c "
        "join pg_namespace n on n.oid = c.relnamespace "
        "where n.nspname = 'public' and c.relkind = 'r'"
    ).fetchall()
    tables = {name: rls for name, rls in rows}
    assert set(tables) == CORE_TABLES
    assert all(tables.values()), "모든 public 테이블에 RLS 가 켜져 있어야 한다"


def test_compliance_seed_matches_kisa_2026_server_items(db: psycopg.Connection) -> None:
    counts: dict[str, int] = dict(
        db.execute(
            "select left(item_code, 1) || ':' || category::text, count(*)::int "
            "from compliance_guidelines group by 1"
        ).fetchall()
    )
    assert counts == {
        "U:account_management": 13,
        "U:directory_file_management": 20,
        "U:service_management": 30,
        "U:patch_management": 1,
        "U:log_management": 3,
        "W:account_management": 14,
        "W:service_management": 23,
        "W:patch_management": 2,
        "W:log_management": 4,
        "W:security_management": 21,
    }
    assert _one(db, "select name from compliance_guidelines where item_code = 'U-01'") == (
        "root 계정 원격 접속 제한"
    )
    assert _one(db, "select name from compliance_guidelines where item_code = 'U-43'") == (
        "NIS, NIS+ 점검"
    )


def test_compliance_guidelines_readable_but_not_writable_by_users(
    db: psycopg.Connection, sample: Sample
) -> None:
    with as_role(db, "authenticated", sample.viewer_a):
        assert _count(db, "select count(*) from compliance_guidelines") > 0
        with expect_error(db, errors.InsufficientPrivilege):
            db.execute("update compliance_guidelines set name = 'x' where item_code = 'U-01'")


# --- 정상 흐름: 결과 생성 → 수동 판정 변경 → 감사 내역 조회 ----------------------------------


def test_override_updates_result_and_records_audit(db: psycopg.Connection, sample: Sample) -> None:
    with as_role(db, "authenticated", sample.operator_a):
        _override(db, sample.result_a, "good", REASON)

    with as_role(db, "authenticated", sample.owner_a):
        assert (
            _one(
                db,
                "select final_status::text from inspection_item_results where id = %s",
                (sample.result_a,),
            )
            == "good"
        )
        audit = db.execute(
            "select a.previous_status::text, a.new_status::text, a.override_reason, u.auth_user_id "
            "from override_audit_logs a join users u on u.id = a.actor_user_id "
            "where a.inspection_item_result_id = %s",
            (sample.result_a,),
        ).fetchall()
    assert audit == [("vulnerable", "good", REASON, sample.operator_a)]


def test_override_with_same_status_is_idempotent(db: psycopg.Connection, sample: Sample) -> None:
    with as_role(db, "authenticated", sample.owner_a):
        _override(db, sample.result_a, "vulnerable", REASON)
    assert _count(db, "select count(*) from override_audit_logs") == 0


@pytest.mark.parametrize("reason", [None, "", "    ", "짧음"])
def test_override_requires_reason_of_five_chars(
    db: psycopg.Connection, sample: Sample, reason: str | None
) -> None:
    with (
        as_role(db, "authenticated", sample.operator_a),
        expect_error(db, errors.InvalidParameterValue),
    ):
        _override(db, sample.result_a, "good", reason)
    assert (
        _one(
            db,
            "select final_status::text from inspection_item_results where id = %s",
            (sample.result_a,),
        )
        == "vulnerable"
    )
    assert _count(db, "select count(*) from override_audit_logs") == 0


@pytest.mark.parametrize("actor", ["viewer_a", "suspended_a", "owner_b"])
def test_override_rejected_for_unauthorized_users(
    db: psycopg.Connection, sample: Sample, actor: str
) -> None:
    actor_id: uuid.UUID = getattr(sample, actor)
    with as_role(db, "authenticated", actor_id), expect_error(db, errors.InsufficientPrivilege):
        _override(db, sample.result_a, "good", REASON)
    assert _count(db, "select count(*) from override_audit_logs") == 0


def test_override_not_callable_by_anon(db: psycopg.Connection, sample: Sample) -> None:
    with as_role(db, "anon"), expect_error(db, errors.InsufficientPrivilege):
        _override(db, sample.result_a, "good", REASON)


def test_results_cannot_be_changed_outside_override_function(
    db: psycopg.Connection, sample: Sample
) -> None:
    with as_role(db, "authenticated", sample.owner_a):
        with expect_error(db, errors.InsufficientPrivilege):
            db.execute(
                "update inspection_item_results set final_status = 'good' where id = %s",
                (sample.result_a,),
            )
        with expect_error(db, errors.InsufficientPrivilege):
            db.execute(
                "insert into override_audit_logs (inspection_item_result_id, tenant_id, "
                "actor_user_id, previous_status, new_status, override_reason) "
                "select %s, %s, id, 'vulnerable', 'good', %s from users limit 1",
                (sample.result_a, sample.tenant_a, REASON),
            )


# --- 무결성 · 불변성 -----------------------------------------------------------------------


@pytest.mark.parametrize("score", [0, 4])
def test_asset_cia_score_must_be_between_1_and_3(
    db: psycopg.Connection, sample: Sample, score: int
) -> None:
    with expect_error(db, errors.CheckViolation):
        db.execute(
            "insert into assets (tenant_id, hostname, os_type, confidentiality_score) "
            "values (%s, 'bad-host', 'linux', %s)",
            (sample.tenant_a, score),
        )


@pytest.mark.parametrize("role", ["superuser", "service_role"])
def test_audit_log_is_append_only(db: psycopg.Connection, sample: Sample, role: str) -> None:
    with as_role(db, "authenticated", sample.operator_a):
        _override(db, sample.result_a, "good", REASON)

    statements = [
        "update override_audit_logs set override_reason = '변조된 사유입니다'",
        "delete from override_audit_logs",
        "truncate override_audit_logs",
    ]
    for statement in statements:
        if role == "superuser":
            with expect_error(db, errors.InsufficientPrivilege):
                db.execute(statement)
        else:
            with as_role(db, "service_role"), expect_error(db, errors.InsufficientPrivilege):
                db.execute(statement)
    assert _one(db, "select override_reason from override_audit_logs") == REASON


def test_overridden_result_cannot_be_deleted(db: psycopg.Connection, sample: Sample) -> None:
    with as_role(db, "authenticated", sample.operator_a):
        _override(db, sample.result_a, "good", REASON)
    with expect_error(db, errors.ForeignKeyViolation):
        db.execute("delete from inspection_item_results where id = %s", (sample.result_a,))


def test_result_cannot_mix_tenants(db: psycopg.Connection, sample: Sample) -> None:
    with expect_error(db, errors.ForeignKeyViolation):
        db.execute(
            "insert into inspection_item_results (tenant_id, assessment_run_id, asset_id, "
            "item_code, auto_status, final_status) values (%s, %s, %s, 'U-02', 'good', 'good')",
            (sample.tenant_a, sample.run_a, sample.asset_b),
        )


def test_generated_reports_unique_per_run_type_format(
    db: psycopg.Connection, sample: Sample
) -> None:
    insert = (
        "insert into generated_reports (tenant_id, assessment_run_id, report_type, format, "
        "storage_path, file_size_bytes, expires_at) "
        "values (%s, %s, 'summary', 'pdf', 'reports/a.pdf', 100, now() + interval '1 day')"
    )
    db.execute(insert, (sample.tenant_a, sample.run_a))
    with expect_error(db, errors.UniqueViolation):
        db.execute(insert, (sample.tenant_a, sample.run_a))


# --- 테넌트 격리 (RLS) -----------------------------------------------------------------------

TENANT_SCOPED_QUERIES = {
    "assets": "select count(*) from assets where tenant_id = %s",
    "assessment_runs": "select count(*) from assessment_runs where tenant_id = %s",
    "inspection_item_results": "select count(*) from inspection_item_results where tenant_id = %s",
    "override_audit_logs": "select count(*) from override_audit_logs where tenant_id = %s",
    "users": "select count(*) from users where tenant_id = %s",
    "tenants": "select count(*) from tenants where id = %s",
}


def test_members_only_see_their_own_tenant(db: psycopg.Connection, sample: Sample) -> None:
    with as_role(db, "authenticated", sample.operator_a):
        _override(db, sample.result_a, "good", REASON)

    with as_role(db, "authenticated", sample.viewer_a):
        for table, query in TENANT_SCOPED_QUERIES.items():
            assert _count(db, query, (sample.tenant_a,)) > 0, (
                f"{table}: 자기 테넌트 데이터가 보여야 한다"
            )
            assert _count(db, query, (sample.tenant_b,)) == 0, (
                f"{table}: 다른 테넌트가 보이면 안 된다"
            )

    with as_role(db, "authenticated", sample.owner_b):
        for table, query in TENANT_SCOPED_QUERIES.items():
            assert _count(db, query, (sample.tenant_a,)) == 0, f"{table}: 테넌트 A 가 노출됨"


def test_suspended_and_unaffiliated_users_see_nothing(
    db: psycopg.Connection, sample: Sample
) -> None:
    outsider = _auth_user(db)
    for auth_id in (sample.suspended_a, outsider):
        with as_role(db, "authenticated", auth_id):
            for query in TENANT_SCOPED_QUERIES.values():
                assert _count(db, query, (sample.tenant_a,)) == 0


@pytest.mark.parametrize("table", sorted(CORE_TABLES))
def test_anon_has_no_table_access(db: psycopg.Connection, table: str) -> None:
    with as_role(db, "anon"), expect_error(db, errors.InsufficientPrivilege):
        db.execute(f"select 1 from public.{table} limit 1")  # noqa: S608 - 고정된 테이블 이름 목록


def test_cross_tenant_update_has_no_effect(db: psycopg.Connection, sample: Sample) -> None:
    with as_role(db, "authenticated", sample.owner_b):
        updated = db.execute(
            "update assets set confidentiality_score = 1 where id = %s", (sample.asset_a,)
        ).rowcount
    assert updated == 0
    assert (
        _one(db, "select confidentiality_score from assets where id = %s", (sample.asset_a,)) == 2
    )


def test_asset_importance_editable_by_operator_not_viewer(
    db: psycopg.Connection, sample: Sample
) -> None:
    query = "update assets set availability_score = 3 where id = %s"
    with as_role(db, "authenticated", sample.viewer_a):
        assert db.execute(query, (sample.asset_a,)).rowcount == 0
    with as_role(db, "authenticated", sample.operator_a):
        assert db.execute(query, (sample.asset_a,)).rowcount == 1


def test_users_cannot_change_asset_identity_or_tenant(
    db: psycopg.Connection, sample: Sample
) -> None:
    with (
        as_role(db, "authenticated", sample.owner_a),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        db.execute(
            "update assets set tenant_id = %s where id = %s", (sample.tenant_b, sample.asset_a)
        )


def test_invitations_visible_to_owner_only(db: psycopg.Connection, sample: Sample) -> None:
    user_id = _one(db, "select id from users where auth_user_id = %s", (sample.viewer_a,))
    db.execute(
        "insert into invitations (token_hash, tenant_id, user_id, expires_at) "
        "values (%s, %s, %s, now() + interval '1 day')",
        ("a" * 64, sample.tenant_a, user_id),
    )
    query = "select count(*) from invitations"
    with as_role(db, "authenticated", sample.owner_a):
        assert _count(db, query) == 1
    for other in (sample.operator_a, sample.viewer_a, sample.owner_b):
        with as_role(db, "authenticated", other):
            assert _count(db, query) == 0


def test_only_owner_manages_team_and_risk_policy(db: psycopg.Connection, sample: Sample) -> None:
    add_member = (
        "insert into users (tenant_id, email, name, role, status) "
        "values (%s, 'new@example.com', '신규 팀원', 'viewer', 'invited')"
    )
    add_policy = "insert into risk_scoring_policies (tenant_id) values (%s)"
    with as_role(db, "authenticated", sample.operator_a):
        with expect_error(db, errors.InsufficientPrivilege):
            db.execute(add_member, (sample.tenant_a,))
        with expect_error(db, errors.InsufficientPrivilege):
            db.execute(add_policy, (sample.tenant_a,))
    with (
        as_role(db, "authenticated", sample.owner_b),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        db.execute(add_member, (sample.tenant_a,))
    with as_role(db, "authenticated", sample.owner_a):
        db.execute(add_member, (sample.tenant_a,))
        db.execute(add_policy, (sample.tenant_a,))

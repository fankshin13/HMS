"""보고서 조판 요청·원본 파기 함수, 보고서 저장소 권한."""

import uuid
from dataclasses import dataclass

import psycopg
import pytest
from psycopg import errors

from tests.db.helpers import _count, _member, _new_id, _one, as_role, expect_error

REQUEST = "select public.request_report_generation(%s, %s)"
PURGE = "select public.purge_raw_diagnostic_data(%s, %s)"


@dataclass(frozen=True)
class Ws:
    tenant: uuid.UUID
    run: uuid.UUID
    owner: uuid.UUID
    operator: uuid.UUID
    viewer: uuid.UUID
    outsider: uuid.UUID


@pytest.fixture
def ws(db: psycopg.Connection) -> Ws:
    tenant = _new_id(db, "insert into tenants (name) values ('보안팀') returning id")
    run = _new_id(
        db,
        "insert into assessment_runs (tenant_id, title, status) values (%s, '진단', 'completed') "
        "returning id",
        (tenant,),
    )
    for name in ("a.txt", "b.txt"):
        db.execute(
            "insert into diagnostic_logs (tenant_id, assessment_run_id, file_name, "
            "file_size_bytes, storage_path, parse_status) values (%s, %s, %s, 10, %s, 'success')",
            (tenant, run, name, f"{tenant}/{run}/{name}"),
        )
    other = _new_id(db, "insert into tenants (name) values ('다른 회사') returning id")
    return Ws(
        tenant=tenant,
        run=run,
        owner=_member(db, tenant, "owner"),
        operator=_member(db, tenant, "operator"),
        viewer=_member(db, tenant, "viewer"),
        outsider=_member(db, other, "owner"),
    )


def _request(db: psycopg.Connection, run: uuid.UUID, force: bool = False) -> dict[str, object]:
    value = _one(db, REQUEST, (run, force))
    assert isinstance(value, dict)
    return value


def _reports(db: psycopg.Connection, ws: Ws, hours: int = 24) -> None:
    for kind in ("detailed", "summary", "risk_plan"):
        for fmt in ("docx", "pdf"):
            db.execute(
                "insert into generated_reports (tenant_id, assessment_run_id, report_type, format, "
                "storage_path, file_size_bytes, expires_at) "
                "values (%s, %s, %s, %s, %s, 100, now() + make_interval(hours => %s))",
                (ws.tenant, ws.run, kind, fmt, f"{ws.tenant}/{ws.run}/{kind}.{fmt}", hours),
            )


def test_operator_queues_generation_once(db: psycopg.Connection, ws: Ws) -> None:
    with as_role(db, "authenticated", ws.operator):
        first = _request(db, ws.run)
        second = _request(db, ws.run)
    assert (first["status"], first["dispatched"]) == ("queued", True)
    assert (second["status"], second["dispatched"]) == ("queued", False)
    assert (
        _count(db, "select count(*) from report_jobs where assessment_run_id = %s", (ws.run,)) == 1
    )


def test_valid_reports_are_reused_unless_forced(db: psycopg.Connection, ws: Ws) -> None:
    with as_role(db, "authenticated", ws.owner):
        _request(db, ws.run)
    db.execute(
        "update report_jobs set status = 'completed' where assessment_run_id = %s", (ws.run,)
    )
    _reports(db, ws)
    with as_role(db, "authenticated", ws.owner):
        reused = _request(db, ws.run)
        forced = _request(db, ws.run, True)
    assert (reused["status"], reused["dispatched"]) == ("completed", False)
    assert (forced["status"], forced["dispatched"]) == ("queued", True)


def test_expired_reports_are_regenerated(db: psycopg.Connection, ws: Ws) -> None:
    with as_role(db, "authenticated", ws.owner):
        _request(db, ws.run)
    db.execute(
        "update report_jobs set status = 'completed' where assessment_run_id = %s", (ws.run,)
    )
    _reports(db, ws, hours=-1)
    with as_role(db, "authenticated", ws.owner):
        assert _request(db, ws.run)["dispatched"] is True


def test_failed_job_can_be_retried(db: psycopg.Connection, ws: Ws) -> None:
    with as_role(db, "authenticated", ws.owner):
        _request(db, ws.run)
    db.execute(
        "update report_jobs set status = 'failed', error_message = 'x' "
        "where assessment_run_id = %s",
        (ws.run,),
    )
    with as_role(db, "authenticated", ws.owner):
        assert _request(db, ws.run)["dispatched"] is True
    row = db.execute(
        "select status::text, error_message from report_jobs where assessment_run_id = %s",
        (ws.run,),
    ).fetchone()
    assert row == ("queued", None)


def test_unfinished_analysis_cannot_be_reported(db: psycopg.Connection, ws: Ws) -> None:
    db.execute("update assessment_runs set status = 'parsing' where id = %s", (ws.run,))
    with (
        as_role(db, "authenticated", ws.operator),
        expect_error(db, errors.ObjectNotInPrerequisiteState),
    ):
        _request(db, ws.run)


@pytest.mark.parametrize("actor", ["viewer", "outsider"])
def test_viewer_and_outsider_cannot_request(db: psycopg.Connection, ws: Ws, actor: str) -> None:
    with (
        as_role(db, "authenticated", getattr(ws, actor)),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        _request(db, ws.run)


def test_jobs_visible_only_to_members_and_not_writable(db: psycopg.Connection, ws: Ws) -> None:
    with as_role(db, "authenticated", ws.owner):
        _request(db, ws.run)
    with as_role(db, "authenticated", ws.viewer):
        assert _count(db, "select count(*) from report_jobs") == 1
    with as_role(db, "authenticated", ws.outsider):
        assert _count(db, "select count(*) from report_jobs") == 0
    with (
        as_role(db, "authenticated", ws.owner),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        db.execute("update report_jobs set status = 'completed'")


def test_purge_clears_paths_and_records_audit(db: psycopg.Connection, ws: Ws) -> None:
    with as_role(db, "authenticated", ws.operator):
        result = _one(db, PURGE, (ws.run, False))
        again = _one(db, PURGE, (ws.run, False))
    assert isinstance(result, dict) and isinstance(again, dict)
    assert result["purged_log_count"] == 2 and again["purged_log_count"] == 0
    assert result["purged_at"] == again["purged_at"]  # 처음 파기 시각 유지
    assert (
        _count(
            db,
            "select count(*) from diagnostic_logs where assessment_run_id = %s "
            "and storage_path is not null",
            (ws.run,),
        )
        == 0
    )
    assert (
        _count(db, "select count(*) from purge_audit_logs where assessment_run_id = %s", (ws.run,))
        == 2
    )
    with expect_error(db, errors.InsufficientPrivilege):
        db.execute("delete from purge_audit_logs")


def test_purge_with_reports_removes_report_rows(db: psycopg.Connection, ws: Ws) -> None:
    _reports(db, ws)
    with as_role(db, "authenticated", ws.owner):
        _one(db, PURGE, (ws.run, True))
    assert (
        _count(db, "select count(*) from generated_reports where assessment_run_id = %s", (ws.run,))
        == 0
    )


@pytest.mark.parametrize("actor", ["viewer", "outsider"])
def test_viewer_and_outsider_cannot_purge(db: psycopg.Connection, ws: Ws, actor: str) -> None:
    with (
        as_role(db, "authenticated", getattr(ws, actor)),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        _one(db, PURGE, (ws.run, False))


# --- 보고서 저장소 ---------------------------------------------------------------------------


def test_report_objects_readable_by_members_only(db: psycopg.Connection, ws: Ws) -> None:
    assert _one(db, "select public from storage.buckets where id = 'reports'") is False
    path = f"{ws.tenant}/{ws.run}/detailed.pdf"
    db.execute("insert into storage.objects (bucket_id, name) values ('reports', %s)", (path,))
    count = "select count(*) from storage.objects where bucket_id = 'reports' and name = %s"
    with as_role(db, "authenticated", ws.viewer):
        assert _count(db, count, (path,)) == 1
        assert db.execute("delete from storage.objects where name = %s", (path,)).rowcount == 0
    with as_role(db, "authenticated", ws.outsider):
        assert _count(db, count, (path,)) == 0
    with (
        as_role(db, "authenticated", ws.operator),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        db.execute(
            "insert into storage.objects (bucket_id, name) values ('reports', %s)",
            (f"{ws.tenant}/{ws.run}/forged.pdf",),
        )
    with as_role(db, "authenticated", ws.operator):
        assert db.execute("delete from storage.objects where name = %s", (path,)).rowcount == 1

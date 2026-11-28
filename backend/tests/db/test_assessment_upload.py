"""진단 파일 업로드 등록 함수와 원본 로그 저장소 권한."""

import hashlib
import json
import uuid
from dataclasses import dataclass

import psycopg
import pytest
from psycopg import errors

from tests.db.helpers import _auth_user, _count, _member, _new_id, _one, as_role, expect_error

SHA = hashlib.sha256(b"archive").hexdigest()


@dataclass(frozen=True)
class Workspace:
    tenant: uuid.UUID
    owner: uuid.UUID
    operator: uuid.UUID
    viewer: uuid.UUID
    other_owner: uuid.UUID
    other_tenant: uuid.UUID


@pytest.fixture
def ws(db: psycopg.Connection) -> Workspace:
    tenant = _new_id(db, "insert into tenants (name) values ('보안팀') returning id")
    other = _new_id(db, "insert into tenants (name) values ('다른 회사') returning id")
    return Workspace(
        tenant=tenant,
        owner=_member(db, tenant, "owner"),
        operator=_member(db, tenant, "operator"),
        viewer=_member(db, tenant, "viewer"),
        other_owner=_member(db, other, "owner"),
        other_tenant=other,
    )


def _log(tenant: uuid.UUID, run: uuid.UUID, name: str, **extra: object) -> dict[str, object]:
    base: dict[str, object] = {
        "file_name": name,
        "file_size_bytes": 1024,
        "storage_path": f"{tenant}/{run}/{name}",
        "parse_status": "success",
        "quarantined_error_lines": 0,
    }
    base.update(extra)
    return base


def _register(
    conn: psycopg.Connection,
    tenant: uuid.UUID,
    run: uuid.UUID,
    logs: list[dict[str, object]],
    *,
    sha: str = SHA,
    allow_duplicate: bool = False,
) -> dict[str, object]:
    result = _one(
        conn,
        "select public.register_assessment_upload(%s, %s, %s, %s, %s::jsonb, %s)",
        (run, tenant, "2026-11-27 인프라 정기 진단", sha, json.dumps(logs), allow_duplicate),
    )
    assert isinstance(result, dict)
    return result


def _sample_logs(tenant: uuid.UUID, run: uuid.UUID) -> list[dict[str, object]]:
    return [
        _log(
            tenant,
            run,
            "web-01.txt",
            hostname="web-01",
            os_type="linux",
            os_version="Ubuntu 24.04",
            detected_ip="MASKED_IP_001",
        ),
        _log(tenant, run, "win-01.txt", hostname="WIN-01", os_type="windows"),
        _log(
            tenant,
            run,
            "broken.txt",
            parse_status="partial_error",
            quarantined_error_lines=3,
            error_details={"reason": "missing_header"},
        ),
    ]


def test_operator_registers_upload_with_quarantine(db: psycopg.Connection, ws: Workspace) -> None:
    run = uuid.uuid4()
    with as_role(db, "authenticated", ws.operator):
        result = _register(db, ws.tenant, run, _sample_logs(ws.tenant, run))

    assert result["assessment_run_id"] == str(run)
    assert result["status"] == "queued"
    assert result["total_assets"] == 2
    assert result["quarantined_files"] == 1
    preview = result["assets_preview"]
    assert isinstance(preview, list)
    assert [(p["hostname"], p["parse_status"]) for p in preview] == [
        ("web-01", "success"),
        ("WIN-01", "success"),
        (None, "partial_error"),
    ]
    assert _one(db, "select raw_archive_sha256 from assessment_runs where id = %s", (run,)) == SHA
    assert (
        _count(db, "select count(*) from diagnostic_logs where assessment_run_id = %s", (run,)) == 3
    )
    assert (
        _one(db, "select asset_id is null from diagnostic_logs where file_name = 'broken.txt'")
        is True
    )
    assert _count(db, "select count(*) from assets where tenant_id = %s", (ws.tenant,)) == 2


def test_reupload_reuses_assets_by_hostname(db: psycopg.Connection, ws: Workspace) -> None:
    with as_role(db, "authenticated", ws.owner):
        first, second = uuid.uuid4(), uuid.uuid4()
        _register(db, ws.tenant, first, _sample_logs(ws.tenant, first))
        _register(
            db,
            ws.tenant,
            second,
            _sample_logs(ws.tenant, second),
            sha=hashlib.sha256(b"other").hexdigest(),
        )
    assert _count(db, "select count(*) from assets where tenant_id = %s", (ws.tenant,)) == 2


@pytest.mark.parametrize("actor", ["viewer", "other_owner"])
def test_viewers_and_outsiders_cannot_register(
    db: psycopg.Connection, ws: Workspace, actor: str
) -> None:
    run = uuid.uuid4()
    with (
        as_role(db, "authenticated", getattr(ws, actor)),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        _register(db, ws.tenant, run, _sample_logs(ws.tenant, run))
    assert _count(db, "select count(*) from assessment_runs") == 0


def test_anon_cannot_register(db: psycopg.Connection, ws: Workspace) -> None:
    run = uuid.uuid4()
    with as_role(db, "anon"), expect_error(db, errors.InsufficientPrivilege):
        _register(db, ws.tenant, run, _sample_logs(ws.tenant, run))


def test_duplicate_within_ten_minutes_needs_confirmation(
    db: psycopg.Connection, ws: Workspace
) -> None:
    with as_role(db, "authenticated", ws.operator):
        first = uuid.uuid4()
        _register(db, ws.tenant, first, _sample_logs(ws.tenant, first))
        second = uuid.uuid4()
        with expect_error(db, errors.UniqueViolation):
            _register(db, ws.tenant, second, _sample_logs(ws.tenant, second))
        _register(db, ws.tenant, second, _sample_logs(ws.tenant, second), allow_duplicate=True)
    assert _count(db, "select count(*) from assessment_runs") == 2


def test_storage_path_must_stay_in_run_folder(db: psycopg.Connection, ws: Workspace) -> None:
    run = uuid.uuid4()
    bad_paths = [
        f"{ws.other_tenant}/{run}/x.txt",
        f"{ws.tenant}/{uuid.uuid4()}/x.txt",
        f"{ws.tenant}/{run}/../../x.txt",
    ]
    for path in bad_paths:
        with (
            as_role(db, "authenticated", ws.operator),
            expect_error(db, errors.InvalidParameterValue),
        ):
            _register(db, ws.tenant, run, [_log(ws.tenant, run, "x.txt", storage_path=path)])
    assert _count(db, "select count(*) from assessment_runs") == 0


@pytest.mark.parametrize(
    ("title", "sha", "logs"),
    [("", SHA, None), ("x" * 201, SHA, None), ("진단", "not-a-hash", None), ("진단", SHA, [])],
)
def test_invalid_input_is_rejected(
    db: psycopg.Connection, ws: Workspace, title: str, sha: str, logs: list[object] | None
) -> None:
    run = uuid.uuid4()
    payload = _sample_logs(ws.tenant, run) if logs is None else logs
    with (
        as_role(db, "authenticated", ws.operator),
        expect_error(db, errors.InvalidParameterValue),
    ):
        db.execute(
            "select public.register_assessment_upload(%s, %s, %s, %s, %s::jsonb)",
            (run, ws.tenant, title, sha, json.dumps(payload)),
        )


# --- 원본 로그 저장소(storage.objects) 권한 ---------------------------------------------------

INSERT_OBJECT = "insert into storage.objects (bucket_id, name) values ('diagnostic-raw', %s)"


def test_bucket_is_private(db: psycopg.Connection) -> None:
    assert _one(db, "select public from storage.buckets where id = 'diagnostic-raw'") is False


def test_operator_can_store_and_read_own_tenant_logs(db: psycopg.Connection, ws: Workspace) -> None:
    path = f"{ws.tenant}/{uuid.uuid4()}/web-01.txt"
    with as_role(db, "authenticated", ws.operator):
        db.execute(INSERT_OBJECT, (path,))
        assert _count(db, "select count(*) from storage.objects where name = %s", (path,)) == 1
        assert db.execute("delete from storage.objects where name = %s", (path,)).rowcount == 1


@pytest.mark.parametrize("actor", ["viewer", "other_owner"])
def test_others_cannot_store_logs(db: psycopg.Connection, ws: Workspace, actor: str) -> None:
    path = f"{ws.tenant}/{uuid.uuid4()}/web-01.txt"
    with (
        as_role(db, "authenticated", getattr(ws, actor)),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        db.execute(INSERT_OBJECT, (path,))


def test_others_cannot_read_stored_logs(db: psycopg.Connection, ws: Workspace) -> None:
    path = f"{ws.tenant}/{uuid.uuid4()}/web-01.txt"
    db.execute(INSERT_OBJECT, (path,))
    for actor in (ws.viewer, ws.other_owner, _auth_user(db)):
        with as_role(db, "authenticated", actor):
            assert _count(db, "select count(*) from storage.objects where name = %s", (path,)) == 0


def test_malformed_folder_is_denied_not_crashing(db: psycopg.Connection, ws: Workspace) -> None:
    with (
        as_role(db, "authenticated", ws.operator),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        db.execute(INSERT_OBJECT, ("not-a-uuid/run/x.txt",))

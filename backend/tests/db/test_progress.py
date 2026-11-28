"""진단 진행률 집계 함수: 소속 멤버만 볼 수 있고 숫자가 정확한지."""

import uuid
from dataclasses import dataclass

import psycopg
import pytest
from psycopg import errors

from tests.db.helpers import _auth_user, _member, _new_id, as_role, expect_error

PROGRESS = "select * from public.get_assessment_progress(%s)"


@dataclass(frozen=True)
class ProgressRun:
    run: uuid.UUID
    viewer: uuid.UUID
    outsider: uuid.UUID


@pytest.fixture
def run(db: psycopg.Connection) -> ProgressRun:
    tenant = _new_id(db, "insert into tenants (name) values ('보안팀') returning id")
    viewer = _member(db, tenant, "viewer")
    run = _new_id(
        db,
        "insert into assessment_runs (tenant_id, title, status, total_assets) "
        "values (%s, '진단', 'parsing', 3) returning id",
        (tenant,),
    )
    for host, statuses in (("a", ["good", "vulnerable"]), ("b", ["na"])):
        asset = _new_id(
            db,
            "insert into assets (tenant_id, hostname, os_type) "
            "values (%s, %s, 'linux') returning id",
            (tenant, host),
        )
        for code, status in zip(["U-01", "U-02"], statuses, strict=False):
            db.execute(
                "insert into inspection_item_results (tenant_id, assessment_run_id, asset_id, "
                "item_code, auto_status, final_status) values (%s, %s, %s, %s, %s, %s)",
                (tenant, run, asset, code, status, status),
            )
    db.execute(
        "insert into diagnostic_logs (tenant_id, assessment_run_id, file_name, file_size_bytes, "
        "storage_path, parse_status) values (%s, %s, 'x.txt', 1, %s, 'partial_error')",
        (tenant, run, f"{tenant}/{run}/x.txt"),
    )
    other_tenant = _new_id(db, "insert into tenants (name) values ('다른 회사') returning id")
    return ProgressRun(run=run, viewer=viewer, outsider=_member(db, other_tenant, "owner"))


def test_member_sees_accurate_progress(db: psycopg.Connection, run: ProgressRun) -> None:
    with as_role(db, "authenticated", run.viewer):
        row = db.execute(PROGRESS, (run.run,)).fetchone()
    assert row == ("parsing", 3, 2, 1, 3, 1, 1, 1)


def test_other_tenant_and_strangers_get_nothing(db: psycopg.Connection, run: ProgressRun) -> None:
    for who in (run.outsider, _auth_user(db)):
        with as_role(db, "authenticated", who):
            assert db.execute(PROGRESS, (run.run,)).fetchall() == []


def test_anon_cannot_call(db: psycopg.Connection, run: ProgressRun) -> None:
    with as_role(db, "anon"), expect_error(db, errors.InsufficientPrivilege):
        db.execute(PROGRESS, (run.run,))

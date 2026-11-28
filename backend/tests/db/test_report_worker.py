"""보고서 조판 워커: 6개 산출물 원자적 저장·실패 처리·보존 기한 관리(실제 로컬 DB)."""

import io
import time
import uuid
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime

import psycopg
import pytest

from modules.worker.reports import (
    claim_next_report_job,
    generate_reports,
    load_report_data,
    purge_expired,
)
from modules.worker.tasks import run_assessment_parsing
from tests.db.test_worker import UBUNTU, WINDOWS, MemorySource, Run, make_run

NOW = datetime(2026, 11, 28, 3, 0, tzinfo=UTC)


class MemoryStore:
    def __init__(self, fail_on: str | None = None) -> None:
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.deleted: list[str] = []
        self.fail_on = fail_on

    def put(self, path: str, content: bytes, content_type: str) -> None:
        if self.fail_on and path.endswith(self.fail_on):
            raise ConnectionError("storage unavailable")
        self.objects[path] = (content, content_type)

    def delete(self, paths: list[str]) -> None:
        for path in paths:
            self.deleted.append(path)
            self.objects.pop(path, None)


@pytest.fixture
def conn(database_url: str) -> Iterator[psycopg.Connection]:
    with psycopg.connect(database_url, autocommit=True) as connection:
        yield connection


def analyzed(conn: psycopg.Connection, hosts: int = 2) -> Run:
    logs = [("WIN-SRV-01", "windows", WINDOWS)] + [
        (f"host-{i:02d}", "linux", UBUNTU.replace("ubuntu-01", f"host-{i:02d}"))
        for i in range(hosts - 1)
    ]
    run = make_run(conn, [*logs, (None, "linux", "not a result")])
    run_assessment_parsing(conn, run.run, run.tenant, MemorySource(run.files))
    return run


def queue(conn: psycopg.Connection, run: Run) -> None:
    conn.execute(
        "insert into report_jobs (assessment_run_id, tenant_id) values (%s, %s)",
        (run.run, run.tenant),
    )


def override(conn: psycopg.Connection, run: Run) -> None:
    """감사 부록 확인용: 취약 항목 하나를 담당자가 양호로 바꾼 기록."""
    user = conn.execute(
        "insert into users (tenant_id, email, name, role, status) "
        "values (%s, 'kim@example.com', '김보안', 'owner', 'active') returning id",
        (run.tenant,),
    ).fetchone()
    item = conn.execute(
        "select id from inspection_item_results where assessment_run_id = %s "
        "and final_status = 'vulnerable' order by item_code limit 1",
        (run.run,),
    ).fetchone()
    assert user and item
    conn.execute("update inspection_item_results set final_status = 'good' where id = %s", item)
    conn.execute(
        "insert into override_audit_logs (inspection_item_result_id, tenant_id, actor_user_id, "
        "previous_status, new_status, override_reason) "
        "values (%s, %s, %s, 'vulnerable', 'good', '방화벽 대체 통제로 예외 승인')",
        (item[0], run.tenant, user[0]),
    )


def test_job_produces_six_files_atomically(conn: psycopg.Connection) -> None:
    run = analyzed(conn)
    override(conn, run)
    queue(conn, run)
    store = MemoryStore()
    claimed = claim_next_report_job(conn)
    assert claimed == (run.run, run.tenant)
    summary = generate_reports(conn, run.run, run.tenant, store, now=NOW, parallel=False)

    assert (summary.status, summary.files) == ("completed", 6)
    assert sorted(p.rsplit("/", 1)[1] for p in store.objects) == [
        "detailed.docx",
        "detailed.pdf",
        "risk_plan.docx",
        "risk_plan.pdf",
        "summary.docx",
        "summary.pdf",
    ]
    assert all(p.startswith(f"{run.tenant}/{run.run}/") for p in store.objects)
    rows = conn.execute(
        "select report_type::text, format::text, file_size_bytes, "
        "expires_at - created_at > interval '23 hours' "
        "from generated_reports where assessment_run_id = %s order by 1, 2",
        (run.run,),
    ).fetchall()
    assert len(rows) == 6 and all(r[2] > 0 and r[3] for r in rows)
    job = conn.execute(
        "select status::text, progress_percentage, current_step from report_jobs "
        "where assessment_run_id = %s",
        (run.run,),
    ).fetchone()
    assert job == ("completed", 100, "completed")

    risk_plan = store.objects[f"{run.tenant}/{run.run}/risk_plan.docx"][0]
    with zipfile.ZipFile(io.BytesIO(risk_plan)) as archive:
        xml = archive.read("word/document.xml").decode()
    assert "방화벽 대체 통제로 예외 승인" in xml and "김보안" in xml
    assert store.objects[f"{run.tenant}/{run.run}/summary.pdf"][1] == "application/pdf"


def test_report_data_reflects_final_results(conn: psycopg.Connection) -> None:
    run = analyzed(conn, hosts=3)
    data = load_report_data(conn, run.run, run.tenant, NOW)
    assert [a.hostname for a in data.assets] == ["WIN-SRV-01", "host-00", "host-01"]
    assert [len(a.items) for a in data.assets] == [32, 41, 41]
    assert data.quarantined and data.quarantined[0].hostname is None
    item = next(i for i in data.assets[1].items if i.code == "U-18")
    assert item.final_status == "vulnerable" and item.score > 0
    assert item.reason.startswith("/etc/shadow") and "OWNER=root" in item.evidence


def test_upload_failure_marks_job_failed_and_cleans_up(conn: psycopg.Connection) -> None:
    run = analyzed(conn)
    queue(conn, run)
    claim_next_report_job(conn)
    store = MemoryStore(fail_on="summary.docx")
    summary = generate_reports(conn, run.run, run.tenant, store, now=NOW, parallel=False)
    assert summary.status == "failed"
    job = conn.execute(
        "select status::text, error_message from report_jobs where assessment_run_id = %s",
        (run.run,),
    ).fetchone()
    assert job is not None and job[0] == "failed" and "storage unavailable" in job[1]
    assert store.objects == {}  # 일부만 남지 않는다
    assert conn.execute(
        "select count(*) from generated_reports where assessment_run_id = %s", (run.run,)
    ).fetchone() == (0,)
    # 원본 데이터는 보존
    assert conn.execute(
        "select status::text from assessment_runs where id = %s", (run.run,)
    ).fetchone() == ("completed",)


def test_stale_rendering_job_is_reclaimed(conn: psycopg.Connection) -> None:
    run = analyzed(conn)
    queue(conn, run)
    assert claim_next_report_job(conn) is not None
    assert claim_next_report_job(conn) is None  # 진행 중
    conn.execute(
        "update report_jobs set started_at = now() - interval '16 minutes' "
        "where assessment_run_id = %s",
        (run.run,),
    )
    assert claim_next_report_job(conn) == (run.run, run.tenant)


def test_fifty_hosts_render_within_180_seconds(conn: psycopg.Connection) -> None:
    run = analyzed(conn, hosts=50)
    queue(conn, run)
    claim_next_report_job(conn)
    started = time.perf_counter()
    summary = generate_reports(conn, run.run, run.tenant, MemoryStore(), now=NOW)
    elapsed = time.perf_counter() - started
    assert (summary.status, summary.files) == ("completed", 6)
    assert elapsed < 180, f"{elapsed:.1f}s"


def test_housekeeping_expires_reports_and_purges_raw_logs(conn: psycopg.Connection) -> None:
    run = analyzed(conn)
    queue(conn, run)
    claim_next_report_job(conn)
    store = MemoryStore()
    generate_reports(conn, run.run, run.tenant, store, now=NOW, parallel=False)
    raw = MemoryStore()

    kept = purge_expired(conn, store, raw)
    assert (kept.expired_reports, kept.purged_runs) == (0, 0)

    conn.execute(
        "update generated_reports set expires_at = now() - interval '1 minute' "
        "where assessment_run_id = %s",
        (run.run,),
    )
    conn.execute(
        "update report_jobs set completed_at = now() - interval '25 hours' "
        "where assessment_run_id = %s",
        (run.run,),
    )
    kept = purge_expired(conn, store, raw)
    assert (kept.expired_reports, kept.purged_runs) == (6, 1)  # 제로 리텐션(기본값) 원본도 파기
    assert store.objects == {}
    assert conn.execute(
        "select count(*) from report_jobs where assessment_run_id = %s", (run.run,)
    ).fetchone() == (0,)


def test_zero_retention_purges_raw_logs_after_retention(conn: psycopg.Connection) -> None:
    run = analyzed(conn)
    queue(conn, run)
    claim_next_report_job(conn)
    generate_reports(conn, run.run, run.tenant, MemoryStore(), now=NOW, parallel=False)
    conn.execute(
        "update report_jobs set completed_at = now() - interval '25 hours' "
        "where assessment_run_id = %s",
        (run.run,),
    )
    raw = MemoryStore()
    kept = purge_expired(conn, MemoryStore(), raw)
    assert kept.purged_runs == 1
    assert sorted(raw.deleted) == sorted(run.files)
    remaining = conn.execute(
        "select count(*) from diagnostic_logs where assessment_run_id = %s "
        "and storage_path is not null",
        (run.run,),
    ).fetchone()
    assert remaining == (0,)
    audit = conn.execute(
        "select trigger, actor_user_id, purged_log_count from purge_audit_logs "
        "where assessment_run_id = %s",
        (run.run,),
    ).fetchall()
    assert audit == [("expiry", None, len(run.files))]
    # 이미 파기한 차수는 다시 대상이 되지 않는다
    assert purge_expired(conn, MemoryStore(), MemoryStore()).purged_runs == 0


def test_tenant_without_zero_retention_keeps_raw_logs(conn: psycopg.Connection) -> None:
    run = analyzed(conn)
    conn.execute("update tenants set zero_retention_enabled = false where id = %s", (run.tenant,))
    queue(conn, run)
    claim_next_report_job(conn)
    generate_reports(conn, run.run, run.tenant, MemoryStore(), now=NOW, parallel=False)
    conn.execute(
        "update report_jobs set completed_at = now() - interval '25 hours' "
        "where assessment_run_id = %s",
        (run.run,),
    )
    raw = MemoryStore()
    assert purge_expired(conn, MemoryStore(), raw).purged_runs == 0
    assert raw.deleted == []


def test_missing_run_fails_cleanly(conn: psycopg.Connection) -> None:
    run = analyzed(conn)
    queue(conn, run)
    other = uuid.uuid4()
    summary = generate_reports(conn, run.run, other, MemoryStore(), now=NOW, parallel=False)
    assert summary.status == "failed"

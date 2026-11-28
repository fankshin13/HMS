"""파싱 워커: 실제 로컬 DB 에서 상태 전이·결함 격리·멱등성·장애 처리·처리 시간을 검증한다."""

import time
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import psycopg
import pytest

from modules.worker.tasks import claim_next_run, run_assessment_parsing

FIXTURES = Path(__file__).parents[1] / "fixtures"
UBUNTU = (FIXTURES / "linux_ubuntu_default.txt").read_text()
HARDENED = (FIXTURES / "linux_hardened.txt").read_text()
WINDOWS = (FIXTURES / "windows_default.txt").read_text()


class MemorySource:
    def __init__(self, files: dict[str, str]) -> None:
        self.files = files
        self.reads: list[str] = []

    def read(self, storage_path: str) -> str:
        self.reads.append(storage_path)
        return self.files[storage_path]


class BrokenSource:
    def read(self, storage_path: str) -> str:
        raise ConnectionError(f"storage unavailable: {storage_path}")


@dataclass
class Run:
    tenant: uuid.UUID
    run: uuid.UUID
    files: dict[str, str]


@pytest.fixture
def conn(database_url: str) -> Iterator[psycopg.Connection]:
    with psycopg.connect(database_url, autocommit=True) as connection:
        yield connection


def _one(conn: psycopg.Connection, query: str, params: tuple[object, ...] = ()) -> object:
    row = conn.execute(query, params).fetchone()
    assert row is not None
    return row[0]


def make_run(conn: psycopg.Connection, logs: Sequence[tuple[str | None, str, str]]) -> Run:
    """logs: (hostname|None, os_type, 본문). 업로드가 만든 것과 같은 레코드를 만든다."""
    tenant = uuid.UUID(
        str(_one(conn, "insert into tenants (name) values ('워커 테스트') returning id"))
    )
    run = uuid.UUID(
        str(
            _one(
                conn,
                "insert into assessment_runs (tenant_id, title) values (%s, '진단') returning id",
                (tenant,),
            )
        )
    )
    files: dict[str, str] = {}
    for index, (hostname, os_type, text) in enumerate(logs):
        path = f"{tenant}/{run}/{index:03d}.txt"
        files[path] = text
        asset = None
        if hostname:
            asset = _one(
                conn,
                "insert into assets (tenant_id, hostname, os_type) values (%s, %s, %s) "
                "on conflict (tenant_id, hostname) do update set os_type = excluded.os_type "
                "returning id",
                (tenant, hostname, os_type),
            )
        conn.execute(
            "insert into diagnostic_logs (tenant_id, assessment_run_id, asset_id, file_name, "
            "file_size_bytes, storage_path, parse_status, error_details) "
            "values (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                tenant,
                run,
                asset,
                f"{index:03d}.txt",
                len(text),
                path,
                "success" if hostname else "partial_error",
                None
                if hostname
                else '{"reason": "missing_header", "line": 1, "message": "시작 표시 없음"}',
            ),
        )
    return Run(tenant, run, files)


def run_status(conn: psycopg.Connection, run: uuid.UUID) -> str:
    return str(_one(conn, "select status from assessment_runs where id = %s", (run,)))


def test_run_judges_healthy_logs_and_quarantines_broken_ones(conn: psycopg.Connection) -> None:
    damaged = HARDENED.replace("web-01", "web-02").replace("==== U-18 END ====\n", "")
    r = make_run(
        conn,
        [
            ("ubuntu-01", "linux", UBUNTU),
            ("web-01", "linux", HARDENED),
            ("WIN-SRV-01", "windows", WINDOWS),
            ("web-02", "linux", damaged),
            (None, "linux", "not a result"),
        ],
    )
    summary = run_assessment_parsing(conn, r.run, r.tenant, MemorySource(r.files))

    assert summary.status == "completed" == run_status(conn, r.run)
    assert summary.quarantined_logs == 2
    per_host: dict[str, int] = dict(
        conn.execute(
            "select a.hostname, count(*) from inspection_item_results i "
            "join assets a on a.id = i.asset_id "
            "where i.assessment_run_id = %s group by a.hostname",
            (r.run,),
        ).fetchall()
    )
    assert per_host["ubuntu-01"] == 41 and per_host["web-01"] == 41 and per_host["WIN-SRV-01"] == 32
    assert 0 < per_host["web-02"] < 41  # 손상된 자산도 판정 가능한 항목은 남긴다

    vulnerable = _one(
        conn,
        "select count(*) from inspection_item_results "
        "where assessment_run_id = %s and final_status = 'vulnerable'",
        (r.run,),
    )
    assert (
        summary.vulnerable_items
        == vulnerable
        == _one(conn, "select vulnerable_items_count from assessment_runs where id = %s", (r.run,))
    )
    assert (
        _one(
            conn,
            "select auto_status::text || '/' || final_status::text from inspection_item_results i "
            "join assets a on a.id = i.asset_id "
            "where a.hostname = 'ubuntu-01' and i.item_code = 'U-18' "
            "and i.assessment_run_id = %s",
            (r.run,),
        )
        == "vulnerable/vulnerable"
    )

    quarantined = conn.execute(
        "select file_name, parse_status::text, quarantined_error_lines, error_details "
        "from diagnostic_logs "
        "where assessment_run_id = %s and parse_status <> 'success' order by file_name",
        (r.run,),
    ).fetchall()
    assert [(q[0], q[1]) for q in quarantined] == [
        ("003.txt", "partial_error"),
        ("004.txt", "partial_error"),
    ]
    assert isinstance(quarantined[0][3], list) and any(
        "U-18" in e["reason"] for e in quarantined[0][3]
    )
    assert quarantined[1][3] == [{"line_number": 1, "reason": "시작 표시 없음", "raw_snippet": ""}]
    assert (
        _one(
            conn,
            "select count(*) from assets where tenant_id = %s and last_assessed_at is null",
            (r.tenant,),
        )
        == 0
    )


def test_rerun_is_idempotent(conn: psycopg.Connection) -> None:
    r = make_run(conn, [("ubuntu-01", "linux", UBUNTU)])
    source = MemorySource(r.files)
    first = run_assessment_parsing(conn, r.run, r.tenant, source)
    second = run_assessment_parsing(conn, r.run, r.tenant, source)
    assert first == second
    assert len(source.reads) == 1


def test_wrong_tenant_cannot_claim_run(conn: psycopg.Connection) -> None:
    r = make_run(conn, [("ubuntu-01", "linux", UBUNTU)])
    run_assessment_parsing(conn, r.run, uuid.uuid4(), MemorySource(r.files))
    assert run_status(conn, r.run) == "queued"


def test_storage_outage_marks_run_failed(conn: psycopg.Connection) -> None:
    r = make_run(conn, [("ubuntu-01", "linux", UBUNTU)])
    assert run_assessment_parsing(conn, r.run, r.tenant, BrokenSource()).status == "failed"
    assert (
        _one(conn, "select completed_at is not null from assessment_runs where id = %s", (r.run,))
        is True
    )


def test_duplicate_host_in_one_run_is_quarantined(conn: psycopg.Connection) -> None:
    r = make_run(conn, [("ubuntu-01", "linux", UBUNTU), ("ubuntu-01", "linux", UBUNTU)])
    summary = run_assessment_parsing(conn, r.run, r.tenant, MemorySource(r.files))
    assert (summary.results, summary.quarantined_logs) == (41, 1)


def test_requires_autocommit_connection(database_url: str) -> None:
    with psycopg.connect(database_url) as plain, pytest.raises(ValueError, match="autocommit"):
        run_assessment_parsing(plain, uuid.uuid4(), uuid.uuid4(), MemorySource({}))


def test_claim_next_run_returns_oldest_queued(conn: psycopg.Connection) -> None:
    conn.execute("update assessment_runs set status = 'failed' where status = 'queued'")
    r = make_run(conn, [("ubuntu-01", "linux", UBUNTU)])
    assert claim_next_run(conn) == (r.run, r.tenant)
    run_assessment_parsing(conn, r.run, r.tenant, MemorySource(r.files))
    assert claim_next_run(conn) is None


def test_fifty_hosts_are_judged_well_within_180_seconds(conn: psycopg.Connection) -> None:
    hosts = [
        (f"host-{i:02d}", "linux", UBUNTU.replace("ubuntu-01", f"host-{i:02d}")) for i in range(50)
    ]
    r = make_run(conn, hosts)
    started = time.perf_counter()
    summary = run_assessment_parsing(conn, r.run, r.tenant, MemorySource(r.files))
    elapsed = time.perf_counter() - started
    assert (summary.status, summary.results, summary.quarantined_logs) == ("completed", 2050, 0)
    assert elapsed < 180, elapsed
    print(f"50 hosts judged in {elapsed:.2f}s")


def test_worker_scores_vulnerable_items(conn: psycopg.Connection) -> None:
    r = make_run(conn, [("ubuntu-01", "linux", UBUNTU)])
    run_assessment_parsing(conn, r.run, r.tenant, MemorySource(r.files))
    scores: dict[str, str] = dict(
        conn.execute(
            "select item_code, calculated_risk_score::text from inspection_item_results "
            "where assessment_run_id = %s and item_code in ('U-18', 'U-16')",
            (r.run,),
        ).fetchall()
    )
    # 기본 자산 중요도 2·2·2 = 6, U-18(상) 취약 → 18, U-16 양호 → 0
    assert scores == {"U-18": "18.00", "U-16": "0.00"}

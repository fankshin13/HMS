"""진단 차수 파싱·판정 태스크.

상태 전이: queued → parsing → scoring (치명적 인프라 오류 시 parsing → failed).
이미 queued 가 아닌 차수는 아무것도 바꾸지 않는다(멱등). 로그 하나의 결함은 그 로그만 격리한다.
"""

import logging
from dataclasses import dataclass
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from modules.compliance.guideline_mapper import map_log
from modules.parser.log_parser import ErrorLine, parse_log
from modules.worker.storage import LogSource

logger = logging.getLogger(__name__)

CLAIM_RUN = """
update public.assessment_runs
set status = 'parsing', started_at = coalesce(started_at, now())
where id = %s and tenant_id = %s and status = 'queued'
returning id
"""

FINISH_RUN = """
update public.assessment_runs
set status = 'scoring',
    vulnerable_items_count = (
      select count(*) from public.inspection_item_results
      where assessment_run_id = %(run)s and final_status = 'vulnerable'
    )
where id = %(run)s
"""

TOUCH_ASSETS = """
update public.assets
set last_assessed_at = now()
where id in (
  select distinct asset_id from public.inspection_item_results where assessment_run_id = %s
)
"""

INSERT_RESULT = """
insert into public.inspection_item_results (
  tenant_id, assessment_run_id, asset_id, item_code, auto_status, final_status,
  stdout_snippet, raw_log_start_line, raw_log_end_line
) values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
on conflict (assessment_run_id, asset_id, item_code) do nothing
"""

MARK_LOG = """
update public.diagnostic_logs
set parse_status = %s, quarantined_error_lines = %s, error_details = %s
where id = %s
"""

SUMMARY = """
select r.status::text,
  (select count(*) from public.diagnostic_logs l where l.assessment_run_id = r.id),
  (select count(*) from public.diagnostic_logs l
     where l.assessment_run_id = r.id and l.parse_status <> 'success'),
  (select count(*) from public.inspection_item_results i where i.assessment_run_id = r.id),
  r.vulnerable_items_count
from public.assessment_runs r
where r.id = %s
"""


@dataclass(frozen=True)
class RunSummary:
    assessment_run_id: UUID
    status: str
    processed_logs: int
    quarantined_logs: int
    results: int
    vulnerable_items: int


def _errors_json(errors: list[ErrorLine]) -> list[dict[str, object]]:
    return [
        {"line_number": e.line_number, "reason": e.reason, "raw_snippet": e.raw_snippet}
        for e in errors
    ]


def _upload_errors(details: object) -> list[ErrorLine]:
    """업로드 단계에서 기록한 단일 오류({reason, line, message})를 파서 오류 형식으로 바꾼다."""
    if isinstance(details, dict) and "message" in details:
        line = details.get("line")
        return [ErrorLine(line if isinstance(line, int) else 0, str(details["message"]), "")]
    return [ErrorLine(0, "업로드 단계에서 호스트를 식별하지 못했습니다", "")]


def claim_next_run(conn: psycopg.Connection) -> tuple[UUID, UUID] | None:
    """대기 중인 가장 오래된 차수를 고른다.

    실제 선점은 run_assessment_parsing 의 조건부 갱신으로 한 번만 일어난다.
    """
    with conn.transaction():
        row = conn.execute(
            "select id, tenant_id from public.assessment_runs "
            "where status = 'queued' order by created_at limit 1 for update skip locked"
        ).fetchone()
    return (row[0], row[1]) if row else None


def run_assessment_parsing(
    conn: psycopg.Connection, assessment_run_id: UUID, tenant_id: UUID, source: LogSource
) -> RunSummary:
    """conn 은 autocommit 연결이어야 한다.

    로그 단위로 커밋해 진행률이 보이고, 실패해도 앞선 결과가 남는다.
    """
    if not conn.autocommit:
        raise ValueError("run_assessment_parsing 은 autocommit 연결이 필요합니다")

    with conn.transaction():
        claimed = conn.execute(CLAIM_RUN, (assessment_run_id, tenant_id)).fetchone()
    if claimed is None:
        return _summary(conn, assessment_run_id)

    try:
        _process_logs(conn, assessment_run_id, tenant_id, source)
    except Exception:
        logger.exception("진단 차수 파싱 실패: %s", assessment_run_id)
        with conn.transaction():
            conn.execute(
                "update public.assessment_runs set status = 'failed', completed_at = now() "
                "where id = %s",
                (assessment_run_id,),
            )
        return _summary(conn, assessment_run_id)

    with conn.transaction():
        conn.execute(FINISH_RUN, {"run": assessment_run_id})
        conn.execute(TOUCH_ASSETS, (assessment_run_id,))
    return _summary(conn, assessment_run_id)


def _process_logs(
    conn: psycopg.Connection, run_id: UUID, tenant_id: UUID, source: LogSource
) -> None:
    logs = conn.execute(
        "select id, asset_id, storage_path, error_details from public.diagnostic_logs "
        "where assessment_run_id = %s and tenant_id = %s order by file_name, id",
        (run_id, tenant_id),
    ).fetchall()
    seen_assets: set[UUID] = set()

    for log_id, asset_id, storage_path, upload_details in logs:
        if asset_id is None:
            _mark_log(conn, log_id, _upload_errors(upload_details))
            continue
        if asset_id in seen_assets:
            duplicate = ErrorLine(0, "같은 호스트의 결과 파일이 중복되어 판정하지 않았습니다", "")
            _mark_log(conn, log_id, [duplicate])
            continue
        seen_assets.add(asset_id)

        # 저장소 장애는 예외로 올려 차수 전체를 failed 로 남긴다(사용자에게 재업로드 안내)
        text = source.read(storage_path)
        mapped = map_log(parse_log(text))
        rows = [
            (
                tenant_id,
                run_id,
                asset_id,
                r.item_code,
                r.status,
                r.status,
                r.stdout_snippet,
                r.start_line,
                r.end_line,
            )
            for r in mapped.results
        ]
        with conn.transaction():
            with conn.cursor() as cur:
                cur.executemany(INSERT_RESULT, rows)
            _mark_log(conn, log_id, mapped.errors)


def _mark_log(conn: psycopg.Connection, log_id: UUID, errors: list[ErrorLine]) -> None:
    details = Jsonb(_errors_json(errors)) if errors else None
    status = "partial_error" if errors else "success"
    conn.execute(MARK_LOG, (status, len(errors), details, log_id))


def _summary(conn: psycopg.Connection, run_id: UUID) -> RunSummary:
    row = conn.execute(SUMMARY, (run_id,)).fetchone()
    if row is None:
        raise LookupError(f"진단 차수 {run_id} 가 없습니다")
    return RunSummary(run_id, row[0], row[1], row[2], row[3], row[4])

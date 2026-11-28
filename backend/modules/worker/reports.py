"""3종 보고서 조판 태스크와 보존 기한 관리.

상태 전이(report_jobs): queued → rendering → completed (예외 시 failed, 원본 데이터는 보존).
3종 × 2형식 = 6개 파일을 모두 만든 뒤에만 저장소에 올리고 generated_reports 를 한 트랜잭션으로
바꾼다(일부만 생성되는 일이 없음). 15분 넘게 rendering 인 작업은 중단된 것으로 보고 다시 선점한다.
"""

import logging
import multiprocessing
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import UUID

import psycopg

from modules.renderer.docx_builder import build_docx
from modules.renderer.model import (
    REPORT_TYPES,
    AssetResult,
    ItemRow,
    OverrideRow,
    QuarantinedLog,
    ReportData,
    ReportType,
    RiskLevel,
    RiskPolicyView,
    Status,
)
from modules.renderer.pdf_builder import build_pdf
from modules.renderer.reports import BUILDERS
from modules.worker.storage import ReportStore

logger = logging.getLogger(__name__)

RETENTION = timedelta(hours=24)
STALE_RENDERING = timedelta(minutes=15)
CONTENT_TYPES = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pdf": "application/pdf",
}
STEPS: dict[ReportType, tuple[str, int]] = {
    "detailed": ("detailed", 15),
    "summary": ("summary", 55),
    "risk_plan": ("risk_plan", 70),
}

CLAIM_JOB = """
update public.report_jobs j
set status = 'rendering', started_at = now(), progress_percentage = 5,
    current_step = 'loading', error_message = null
where j.assessment_run_id = (
  select q.assessment_run_id from public.report_jobs q
  where q.status = 'queued' or (q.status = 'rendering' and q.started_at < now() - %s)
  order by q.requested_at
  limit 1
  for update skip locked
)
returning j.assessment_run_id, j.tenant_id
"""

PROGRESS = """
update public.report_jobs set progress_percentage = %s, current_step = %s
where assessment_run_id = %s and status = 'rendering'
"""

FAIL_JOB = """
update public.report_jobs
set status = 'failed', current_step = 'failed', error_message = %s
where assessment_run_id = %s
"""


@dataclass(frozen=True)
class ReportJobSummary:
    assessment_run_id: UUID
    status: str
    files: int
    total_bytes: int
    seconds: float


def claim_next_report_job(conn: psycopg.Connection) -> tuple[UUID, UUID] | None:
    with conn.transaction():
        row = conn.execute(CLAIM_JOB, (STALE_RENDERING,)).fetchone()
    return (row[0], row[1]) if row else None


# --- 데이터 적재 (서비스 계층) -------------------------------------------------------------------

RUN = """
select r.title, r.created_at, t.name,
  coalesce(p.critical_threshold, 15), coalesce(p.warning_threshold, 8),
  coalesce(p.confidentiality_weight, 1.00), coalesce(p.integrity_weight, 1.00),
  coalesce(p.availability_weight, 1.00)
from public.assessment_runs r
join public.tenants t on t.id = r.tenant_id
left join public.risk_scoring_policies p on p.tenant_id = r.tenant_id
where r.id = %s and r.tenant_id = %s
"""

ITEMS = """
select a.id, a.hostname, a.os_type::text, a.os_version,
  a.confidentiality_score, a.integrity_score, a.availability_score,
  i.item_code, g.name, g.category::text, g.risk_level::text,
  i.auto_status::text, i.final_status::text, i.calculated_risk_score,
  coalesce(i.stdout_snippet, ''), i.raw_log_start_line, i.raw_log_end_line,
  coalesce(g.good_condition, ''), coalesce(g.vulnerable_condition, ''),
  coalesce(g.remediation_guide, ''),
  exists (select 1 from public.override_audit_logs o where o.inspection_item_result_id = i.id)
from public.inspection_item_results i
join public.assets a on a.id = i.asset_id
join public.compliance_guidelines g on g.item_code = i.item_code
where i.assessment_run_id = %s
order by a.hostname, a.id, i.item_code
"""

ASSET_ERRORS = """
select asset_id, sum(quarantined_error_lines)
from public.diagnostic_logs
where assessment_run_id = %s and asset_id is not null
group by asset_id
"""

OVERRIDES = """
select o.created_at, a.hostname, i.item_code, g.name, o.previous_status::text,
  o.new_status::text, o.override_reason, u.name, u.email
from public.override_audit_logs o
join public.inspection_item_results i on i.id = o.inspection_item_result_id
join public.assets a on a.id = i.asset_id
join public.compliance_guidelines g on g.item_code = i.item_code
left join public.users u on u.id = o.actor_user_id
where i.assessment_run_id = %s
order by o.created_at, a.hostname, i.item_code
"""

QUARANTINED = """
select l.file_name, a.hostname, l.quarantined_error_lines, l.error_details
from public.diagnostic_logs l
left join public.assets a on a.id = l.asset_id
where l.assessment_run_id = %s and l.parse_status <> 'success'
order by l.file_name
"""

STATUSES: dict[str, Status] = {"good": "good", "vulnerable": "vulnerable", "na": "na"}
LEVELS: dict[str, RiskLevel] = {"high": "high", "medium": "medium", "low": "low"}


def _split_snippet(snippet: str) -> tuple[str, str]:
    head, _, rest = snippet.partition("\n")
    if head.startswith("[판정 근거] "):
        return head.removeprefix("[판정 근거] "), rest
    return "", snippet


def _error_reasons(details: object) -> list[str]:
    if isinstance(details, list):
        return [str(e.get("reason", "")) for e in details if isinstance(e, dict)][:3]
    if isinstance(details, dict) and "message" in details:
        return [str(details["message"])]
    return []


def load_report_data(
    conn: psycopg.Connection, run_id: UUID, tenant_id: UUID, generated_at: datetime
) -> ReportData:
    run = conn.execute(RUN, (run_id, tenant_id)).fetchone()
    if run is None:
        raise LookupError("진단 차수를 찾을 수 없습니다")
    errors: dict[UUID, int] = {
        row[0]: int(row[1] or 0) for row in conn.execute(ASSET_ERRORS, (run_id,)).fetchall()
    }

    assets: list[AssetResult] = []
    current: UUID | None = None
    items: list[ItemRow] = []
    meta: tuple[str, str, str | None, int, int, int] | None = None

    def flush() -> None:
        if current is not None and meta is not None:
            hostname, os_type, os_version, c, i, a = meta
            assets.append(
                AssetResult(
                    hostname,
                    os_type,
                    os_version,
                    c,
                    i,
                    a,
                    list(items),
                    errors.get(current, 0),
                )
            )

    for row in conn.execute(ITEMS, (run_id,)).fetchall():
        asset_id = row[0]
        if asset_id != current:
            flush()
            current, items = asset_id, []
            meta = (row[1], row[2], row[3], row[4], row[5], row[6])
        reason, evidence = _split_snippet(row[14])
        items.append(
            ItemRow(
                code=row[7],
                name=row[8],
                category=row[9],
                risk_level=LEVELS[row[10]],
                auto_status=STATUSES[row[11]],
                final_status=STATUSES[row[12]],
                score=Decimal(row[13]),
                reason=reason,
                evidence=evidence,
                start_line=row[15],
                end_line=row[16],
                good_condition=row[17],
                vulnerable_condition=row[18],
                remediation=row[19],
                overridden=row[20],
            )
        )
    flush()

    overrides = [
        OverrideRow(
            created_at=r[0],
            hostname=r[1],
            code=r[2],
            name=r[3],
            previous=STATUSES[r[4]],
            new=STATUSES[r[5]],
            reason=r[6],
            actor=f"{r[7]} ({r[8]})" if r[7] else "알 수 없음",
        )
        for r in conn.execute(OVERRIDES, (run_id,)).fetchall()
    ]
    quarantined = [
        QuarantinedLog(r[0], r[1], r[2], _error_reasons(r[3]))
        for r in conn.execute(QUARANTINED, (run_id,)).fetchall()
    ]
    return ReportData(
        organization=run[2],
        run_title=run[0],
        run_created_at=run[1],
        generated_at=generated_at,
        policy=RiskPolicyView(run[3], run[4], Decimal(run[5]), Decimal(run[6]), Decimal(run[7])),
        assets=assets,
        overrides=overrides,
        quarantined=quarantined,
    )


# --- 조판 --------------------------------------------------------------------------------------


def render_one(kind: ReportType, data: ReportData) -> tuple[ReportType, bytes, bytes]:
    """보고서 하나의 DOCX·PDF. 별도 프로세스에서 실행할 수 있도록 최상위 함수로 둔다."""
    document = BUILDERS[kind](data)
    return kind, build_docx(document), build_pdf(document)


def render_all(
    data: ReportData, progress: Callable[[str, int], None], *, parallel: bool = True
) -> dict[tuple[ReportType, str], bytes]:
    """3종을 모두 만든다. parallel 이면 보고서마다 프로세스를 나눠 동시에 조판한다."""
    files: dict[tuple[ReportType, str], bytes] = {}
    if parallel:
        context = multiprocessing.get_context("spawn")
        with ProcessPoolExecutor(max_workers=len(REPORT_TYPES), mp_context=context) as pool:
            progress("rendering", 15)
            futures = [pool.submit(render_one, kind, data) for kind in REPORT_TYPES]
            for done, future in enumerate(futures, start=1):
                kind, docx, pdf = future.result()
                files[(kind, "docx")], files[(kind, "pdf")] = docx, pdf
                progress(STEPS[kind][0], 15 + done * 23)
    else:
        for kind in REPORT_TYPES:
            step, percent = STEPS[kind]
            progress(step, percent)
            _, docx, pdf = render_one(kind, data)
            files[(kind, "docx")], files[(kind, "pdf")] = docx, pdf
    return files


def generate_reports(
    conn: psycopg.Connection,
    run_id: UUID,
    tenant_id: UUID,
    store: ReportStore,
    *,
    now: datetime | None = None,
    parallel: bool = True,
) -> ReportJobSummary:
    started = datetime.now(UTC)
    generated_at = now or started

    def progress(step: str, percent: int) -> None:
        conn.execute(PROGRESS, (percent, step, run_id))

    uploaded: list[str] = []
    try:
        data = load_report_data(conn, run_id, tenant_id, generated_at)
        files = render_all(data, progress, parallel=parallel)
        progress("uploading", 88)
        rows = []
        for (kind, fmt), content in files.items():
            path = f"{tenant_id}/{run_id}/{kind}.{fmt}"
            store.put(path, content, CONTENT_TYPES[fmt])
            uploaded.append(path)
            rows.append((tenant_id, run_id, kind, fmt, path, len(content)))
        progress("saving", 96)
        with conn.transaction():
            conn.execute(
                "delete from public.generated_reports where assessment_run_id = %s", (run_id,)
            )
            with conn.cursor() as cur:
                cur.executemany(
                    "insert into public.generated_reports (tenant_id, assessment_run_id, "
                    "report_type, format, storage_path, file_size_bytes, expires_at) "
                    "values (%s, %s, %s, %s, %s, %s, now() + %s)",
                    [(*row, RETENTION) for row in rows],
                )
            conn.execute(
                "update public.report_jobs set status = 'completed', progress_percentage = 100, "
                "current_step = 'completed', completed_at = now() where assessment_run_id = %s",
                (run_id,),
            )
    except Exception as exc:
        logger.exception("보고서 조판 실패: %s", run_id)
        message = f"{type(exc).__name__}: {exc}"[:500]
        conn.execute(FAIL_JOB, (message, run_id))
        if uploaded:
            try:
                store.delete(uploaded)
            except Exception:
                logger.exception("실패한 조판의 임시 산출물 정리 실패: %s", run_id)
        return ReportJobSummary(run_id, "failed", 0, 0, _elapsed(started))
    return ReportJobSummary(
        run_id, "completed", len(files), sum(len(f) for f in files.values()), _elapsed(started)
    )


def _elapsed(started: datetime) -> float:
    return (datetime.now(UTC) - started).total_seconds()


# --- 보존 기한 관리 ----------------------------------------------------------------------------


@dataclass(frozen=True)
class HousekeepingSummary:
    expired_reports: int
    purged_runs: int


def purge_expired(
    conn: psycopg.Connection, reports: ReportStore, raw: ReportStore
) -> HousekeepingSummary:
    """24시간 보존 기한이 지난 보고서를 지우고, 제로 리텐션 테넌트는 원본 로그도 지운다.

    원본 로그 자동 파기 대상: zero_retention_enabled 테넌트에서
    보고서 생성 후 보존 기한이 지난 차수.
    """
    # 원본 파기를 먼저 한다(보고서 만료 처리가 조판 작업 기록을 지우기 전에 대상을 찾아야 함)
    targets = conn.execute(
        """
        select r.id, r.tenant_id,
          array_agg(l.storage_path) filter (where l.storage_path is not null)
        from public.assessment_runs r
        join public.tenants t on t.id = r.tenant_id and t.zero_retention_enabled
        join public.report_jobs j on j.assessment_run_id = r.id and j.status = 'completed'
        left join public.diagnostic_logs l on l.assessment_run_id = r.id
        where r.raw_logs_purged_at is null and j.completed_at <= now() - %s
        group by r.id, r.tenant_id
        """,
        (RETENTION,),
    ).fetchall()
    for run_id, tenant_id, paths in targets:
        if paths:
            raw.delete(list(paths))
        with conn.transaction():
            cleared = conn.execute(
                "update public.diagnostic_logs set storage_path = null "
                "where assessment_run_id = %s and storage_path is not null",
                (run_id,),
            ).rowcount
            conn.execute(
                "update public.assessment_runs set raw_logs_purged_at = now() where id = %s",
                (run_id,),
            )
            conn.execute(
                "insert into public.purge_audit_logs (tenant_id, assessment_run_id, trigger, "
                "purged_log_count) values (%s, %s, 'expiry', %s)",
                (tenant_id, run_id, cleared),
            )
    expired = conn.execute(
        "select assessment_run_id, storage_path from public.generated_reports "
        "where expires_at <= now()"
    ).fetchall()
    if expired:
        reports.delete([row[1] for row in expired])
        runs = sorted({row[0] for row in expired})
        with conn.transaction():
            conn.execute(
                "delete from public.generated_reports where expires_at <= now() "
                "and storage_path = any(%s)",
                ([row[1] for row in expired],),
            )
            conn.execute(
                "delete from public.report_jobs j where j.assessment_run_id = any(%s) "
                "and not exists (select 1 from public.generated_reports g "
                "where g.assessment_run_id = j.assessment_run_id)",
                (runs,),
            )

    return HousekeepingSummary(len(expired), len(targets))

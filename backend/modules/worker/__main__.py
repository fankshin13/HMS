"""진단 워커 실행: uv run python -m modules.worker [--once]

처리 순서: 진단 파싱·판정 대기열 → 보고서 조판 대기열 → (한가할 때) 보존 기한 관리.
필요한 환경 변수: DATABASE_URL(백엔드 전용 DB 접속), SUPABASE_URL,
SUPABASE_SERVICE_ROLE_KEY(시크릿), REPORT_FONT_DIR(선택: Pretendard 글꼴 폴더)
"""

import argparse
import logging
import os
import sys
import time

import psycopg

from modules.worker.reports import claim_next_report_job, generate_reports, purge_expired
from modules.worker.storage import BUCKET, REPORT_BUCKET, SupabaseStorageSource
from modules.worker.tasks import claim_next_run, run_assessment_parsing

IDLE_SECONDS = 2
HOUSEKEEPING_SECONDS = 300


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="대기 중인 진단 차수를 파싱·판정한다")
    parser.add_argument("--once", action="store_true", help="대기열이 빌 때까지 처리하고 종료")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    dsn = os.environ.get("DATABASE_URL", "")
    if not dsn:
        sys.exit("DATABASE_URL 이 필요합니다")
    source = SupabaseStorageSource.from_env()
    reports, raw = source.bucket(REPORT_BUCKET), source.bucket(BUCKET)
    last_housekeeping = 0.0

    with psycopg.connect(dsn, autocommit=True) as conn:
        while True:
            claimed = claim_next_run(conn)
            if claimed is None:
                job = claim_next_report_job(conn)
                if job is not None:
                    result = generate_reports(conn, job[0], job[1], reports)
                    logging.info(
                        "보고서 %s → %s (파일 %d, %d바이트, %.1f초)",
                        result.assessment_run_id,
                        result.status,
                        result.files,
                        result.total_bytes,
                        result.seconds,
                    )
                    continue
                if time.monotonic() - last_housekeeping > HOUSEKEEPING_SECONDS or args.once:
                    kept = purge_expired(conn, reports, raw)
                    last_housekeeping = time.monotonic()
                    if kept.expired_reports or kept.purged_runs:
                        logging.info(
                            "보존 기한 관리: 만료 보고서 %d개 삭제, 원본 자동 파기 %d건",
                            kept.expired_reports,
                            kept.purged_runs,
                        )
                if args.once:
                    return
                time.sleep(IDLE_SECONDS)
                continue
            summary = run_assessment_parsing(conn, claimed[0], claimed[1], source)
            logging.info(
                "진단 차수 %s → %s (로그 %d, 격리 %d, 판정 %d, 취약 %d)",
                summary.assessment_run_id,
                summary.status,
                summary.processed_logs,
                summary.quarantined_logs,
                summary.results,
                summary.vulnerable_items,
            )


if __name__ == "__main__":
    main()

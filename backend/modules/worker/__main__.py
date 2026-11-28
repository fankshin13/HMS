"""진단 파싱 워커 실행: uv run python -m modules.worker [--once]

필요한 환경 변수: DATABASE_URL(백엔드 전용 DB 접속), SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY(시크릿)
"""

import argparse
import logging
import os
import sys
import time

import psycopg

from modules.worker.storage import SupabaseStorageSource
from modules.worker.tasks import claim_next_run, run_assessment_parsing

IDLE_SECONDS = 2


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="대기 중인 진단 차수를 파싱·판정한다")
    parser.add_argument("--once", action="store_true", help="대기열이 빌 때까지 처리하고 종료")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    dsn = os.environ.get("DATABASE_URL", "")
    if not dsn:
        sys.exit("DATABASE_URL 이 필요합니다")
    source = SupabaseStorageSource.from_env()

    with psycopg.connect(dsn, autocommit=True) as conn:
        while True:
            claimed = claim_next_run(conn)
            if claimed is None:
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

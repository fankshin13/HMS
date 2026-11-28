"""로컬 PostgreSQL 에 일회용 데이터베이스를 만들어 Supabase 마이그레이션과 RLS 를 검증한다.

TEST_DATABASE_URL (예: postgresql://user:pass@localhost:5432/postgres) 이 필요하다.
안전을 위해 로컬 호스트만 허용하고, 테스트마다 새 데이터베이스를 만든 뒤 끝나면 삭제한다.
"""

import os
import secrets
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from psycopg import sql

REPO_ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS_DIR = REPO_ROOT / "supabase" / "migrations"
BOOTSTRAP_SQL = Path(__file__).with_name("supabase_bootstrap.sql")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _admin_url() -> str:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip(
            "TEST_DATABASE_URL 이 없어 DB 테스트를 건너뜁니다 (README 의 로컬 DB 테스트 참고)"
        )
    host = urlsplit(url).hostname
    if host not in LOCAL_HOSTS:
        pytest.fail(f"TEST_DATABASE_URL 은 로컬 PostgreSQL 만 허용합니다 (현재 호스트: {host})")
    return url


def _with_database(url: str, dbname: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=f"/{dbname}"))


@pytest.fixture(scope="session")
def database_url() -> Iterator[str]:
    admin_url = _admin_url()
    dbname = f"hms_test_{secrets.token_hex(4)}"
    with psycopg.connect(admin_url, autocommit=True) as admin:
        admin.execute(sql.SQL("create database {}").format(sql.Identifier(dbname)))
    url = _with_database(admin_url, dbname)
    try:
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(BOOTSTRAP_SQL.read_text())
            for migration in sorted(MIGRATIONS_DIR.glob("*.sql")):
                conn.execute(migration.read_text())
        yield url
    finally:
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(
                sql.SQL("drop database if exists {} with (force)").format(sql.Identifier(dbname))
            )


@pytest.fixture
def db(database_url: str) -> Iterator[psycopg.Connection]:
    """테스트 하나를 트랜잭션 하나로 감싸고 끝나면 롤백한다."""
    with psycopg.connect(database_url) as conn:
        yield conn
        conn.rollback()

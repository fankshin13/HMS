"""DB 테스트 공용 도우미: 행 생성, Supabase 역할 전환, 예상 오류 검증."""

import json
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
import pytest


def _one(conn: psycopg.Connection, query: str, params: tuple[object, ...] = ()) -> object:
    row = conn.execute(query, params).fetchone()
    assert row is not None
    return row[0]


def _new_id(conn: psycopg.Connection, query: str, params: tuple[object, ...] = ()) -> uuid.UUID:
    return uuid.UUID(str(_one(conn, query, params)))


def _auth_user(conn: psycopg.Connection, email: str | None = None) -> uuid.UUID:
    """Supabase Auth 계정을 만든다. 이메일을 주지 않으면 '<id>@example.com' 을 쓴다."""
    auth_id = uuid.uuid4()
    conn.execute(
        "insert into auth.users (id, email) values (%s, %s)",
        (auth_id, email or f"{auth_id}@example.com"),
    )
    return auth_id


def _member(
    conn: psycopg.Connection, tenant: uuid.UUID, role: str, status: str = "active"
) -> uuid.UUID:
    auth_id = _auth_user(conn)
    conn.execute(
        "insert into public.users (tenant_id, auth_user_id, email, name, role, status) "
        "values (%s, %s, %s, %s, %s, %s)",
        (tenant, auth_id, f"{auth_id}@example.com", f"{role} 사용자", role, status),
    )
    return auth_id


@contextmanager
def as_role(
    conn: psycopg.Connection, role: str, auth_id: uuid.UUID | None = None
) -> Iterator[None]:
    """Supabase API 요청처럼 역할과 JWT 클레임을 설정한다."""
    claims = json.dumps({"sub": str(auth_id), "role": role}) if auth_id else ""
    conn.execute("select set_config('request.jwt.claims', %s, true)", (claims,))
    conn.execute(f"set local role {role}")
    try:
        yield
    finally:
        conn.execute("reset role")
        conn.execute("select set_config('request.jwt.claims', '', true)")


@contextmanager
def expect_error(conn: psycopg.Connection, error: type[Exception]) -> Iterator[None]:
    """실패해야 하는 문장을 세이브포인트 안에서 실행해 트랜잭션을 계속 쓸 수 있게 한다."""
    with pytest.raises(error), conn.transaction():
        yield


def _count(conn: psycopg.Connection, query: str, params: tuple[object, ...] = ()) -> int:
    return int(str(_one(conn, query, params)))

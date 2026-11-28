"""새 워크스페이스(테넌트)와 소유자 계정을 만들고, 소유자용 1회용 초대 링크를 출력한다.

사용법 (backend 디렉터리에서):
    uv run python -m scripts.provision_owner \\
        --tenant-name "테스트 보안팀" --owner-name "홍길동" --owner-email owner@example.com

필요한 환경 변수: DATABASE_URL, INVITATION_TOKEN_SALT, APP_URL
소유자는 출력된 링크를 열고 매직 링크로 로그인하면 워크스페이스에 연결된다.
"""

import argparse
import hashlib
import os
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlencode

import psycopg

OWNER_INVITE_HOURS = 24


def hash_invitation_token(raw_token: str, salt: str) -> str:
    """초대 토큰 해시. 프론트엔드(frontend/lib/invitations/token.ts)와 같은 규칙이어야 한다."""
    return hashlib.sha256(f"{raw_token}{salt}".encode()).hexdigest()


def _returned(cursor: psycopg.Cursor[tuple[object, ...]]) -> object:
    row = cursor.fetchone()
    if row is None:
        raise RuntimeError("INSERT ... RETURNING 이 행을 돌려주지 않았습니다")
    return row[0]


@dataclass(frozen=True)
class ProvisionResult:
    tenant_id: str
    owner_user_id: str
    invite_url: str
    expires_at: datetime


def provision_owner(
    conn: psycopg.Connection,
    *,
    tenant_name: str,
    owner_name: str,
    owner_email: str,
    salt: str,
    app_url: str,
) -> ProvisionResult:
    raw_token = secrets.token_hex(32)
    with conn.transaction():
        tenant_id = _returned(
            conn.execute(
                "insert into public.tenants (name) values (%s) returning id", (tenant_name.strip(),)
            )
        )
        conn.execute(
            "insert into public.risk_scoring_policies (tenant_id) values (%s)", (tenant_id,)
        )
        owner_user_id = _returned(
            conn.execute(
                "insert into public.users (tenant_id, email, name, role, status) "
                "values (%s, %s, %s, 'owner', 'active') returning id",
                (tenant_id, owner_email.strip().lower(), owner_name.strip()),
            )
        )
        expires_at = _returned(
            conn.execute(
                "insert into public.invitations (token_hash, tenant_id, user_id, expires_at) "
                "values (%s, %s, %s, now() + make_interval(hours => %s)) returning expires_at",
                (
                    hash_invitation_token(raw_token, salt),
                    tenant_id,
                    owner_user_id,
                    OWNER_INVITE_HOURS,
                ),
            )
        )
    if not isinstance(expires_at, datetime):
        raise RuntimeError("만료 시각을 읽지 못했습니다")
    invite_url = f"{app_url.rstrip('/')}/auth/verify?{urlencode({'token': raw_token})}"
    return ProvisionResult(str(tenant_id), str(owner_user_id), invite_url, expires_at)


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"환경 변수 {name} 이(가) 필요합니다.")
    return value


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="워크스페이스와 소유자 계정을 만든다")
    parser.add_argument("--tenant-name", required=True)
    parser.add_argument("--owner-name", required=True)
    parser.add_argument("--owner-email", required=True)
    args = parser.parse_args(argv)

    with psycopg.connect(_required_env("DATABASE_URL")) as conn:
        result = provision_owner(
            conn,
            tenant_name=args.tenant_name,
            owner_name=args.owner_name,
            owner_email=args.owner_email,
            salt=_required_env("INVITATION_TOKEN_SALT"),
            app_url=_required_env("APP_URL"),
        )
    print(f"워크스페이스 ID: {result.tenant_id}")
    print(f"소유자 초대 링크 (만료 {result.expires_at.isoformat()}):")
    print(result.invite_url)
    print("이 링크는 1회용입니다. 소유자 본인에게만 안전한 경로로 전달하세요.")


if __name__ == "__main__":
    main()

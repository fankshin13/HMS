"""초대 온보딩: 발급·철회·조회·수락, 1회용·만료·이메일 일치, 동시 수락, 소유자 프로비저닝."""

import hashlib
import secrets
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

import psycopg
import pytest
from psycopg import errors

from scripts.provision_owner import hash_invitation_token, provision_owner
from tests.db.helpers import _auth_user, _count, _member, _new_id, _one, as_role, expect_error

SALT = "test-salt-value-0123456789"
INVITEE_EMAIL = "invitee@example.com"


@dataclass(frozen=True)
class Team:
    tenant: uuid.UUID
    owner: uuid.UUID
    operator: uuid.UUID
    viewer: uuid.UUID
    other_owner: uuid.UUID


@dataclass(frozen=True)
class Invite:
    raw_token: str
    token_hash: str
    invitation_id: uuid.UUID


@pytest.fixture
def team(db: psycopg.Connection) -> Team:
    tenant = _new_id(db, "insert into tenants (name) values ('테스트 보안팀') returning id")
    other = _new_id(db, "insert into tenants (name) values ('다른 회사') returning id")
    return Team(
        tenant=tenant,
        owner=_member(db, tenant, "owner"),
        operator=_member(db, tenant, "operator"),
        viewer=_member(db, tenant, "viewer"),
        other_owner=_member(db, other, "owner"),
    )


def _create(
    conn: psycopg.Connection,
    tenant: uuid.UUID,
    *,
    email: str = INVITEE_EMAIL,
    role: str = "operator",
    hours: int = 24,
) -> Invite:
    """현재 역할로 create_invitation 을 호출한다(역할 전환은 호출하는 쪽에서)."""
    raw = secrets.token_hex(32)
    token_hash = hash_invitation_token(raw, SALT)
    invitation_id = _new_id(
        conn,
        "select invitation_id from public.create_invitation(%s, %s, %s, %s, %s, %s)",
        (tenant, email, "홍길동 컨설턴트", role, token_hash, hours),
    )
    return Invite(raw, token_hash, invitation_id)


def _invite(
    conn: psycopg.Connection,
    actor: uuid.UUID,
    tenant: uuid.UUID,
    *,
    email: str = INVITEE_EMAIL,
    role: str = "operator",
    hours: int = 24,
) -> Invite:
    with as_role(conn, "authenticated", actor):
        return _create(conn, tenant, email=email, role=role, hours=hours)


def _inspect(conn: psycopg.Connection, token_hash: str, role: str = "anon") -> tuple[object, ...]:
    with as_role(conn, role):
        row = conn.execute(
            "select status, tenant_name, user_name, email, role::text "
            "from public.inspect_invitation(%s)",
            (token_hash,),
        ).fetchone()
    assert row is not None
    return tuple(row)


def _accept(conn: psycopg.Connection, auth_id: uuid.UUID, token_hash: str) -> str:
    with as_role(conn, "authenticated", auth_id):
        return str(_one(conn, "select status from public.accept_invitation(%s)", (token_hash,)))


# --- 발급 ----------------------------------------------------------------------------------


def test_owner_creates_invitation_for_new_user(db: psycopg.Connection, team: Team) -> None:
    invite = _invite(db, team.owner, team.tenant, email="  Invitee@Example.com ", hours=48)

    user = db.execute(
        "select u.email, u.role::text, u.status::text, u.auth_user_id, "
        "round(extract(epoch from i.expires_at - now()) / 3600) "
        "from invitations i join users u on u.id = i.user_id where i.id = %s",
        (invite.invitation_id,),
    ).fetchone()
    assert user == (INVITEE_EMAIL, "operator", "invited", None, 48)
    stored_hash = _one(
        db, "select token_hash from invitations where id = %s", (invite.invitation_id,)
    )
    assert stored_hash == invite.token_hash
    assert invite.raw_token not in str(stored_hash)


@pytest.mark.parametrize("actor", ["operator", "viewer", "other_owner"])
def test_non_owners_cannot_create_invitations(
    db: psycopg.Connection, team: Team, actor: str
) -> None:
    with (
        as_role(db, "authenticated", getattr(team, actor)),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        _create(db, team.tenant)
    assert _count(db, "select count(*) from invitations") == 0


def test_anon_cannot_create_invitations(db: psycopg.Connection, team: Team) -> None:
    with as_role(db, "anon"), expect_error(db, errors.InsufficientPrivilege):
        db.execute(
            "select public.create_invitation(%s, %s, 'x', 'viewer', %s, 24)",
            (team.tenant, INVITEE_EMAIL, "a" * 64),
        )


@pytest.mark.parametrize(
    ("email", "role", "hours"),
    [
        ("not-an-email", "operator", 24),
        (INVITEE_EMAIL, "owner", 24),
        (INVITEE_EMAIL, "operator", 0),
        (INVITEE_EMAIL, "operator", 73),
    ],
)
def test_invalid_invitation_input_is_rejected(
    db: psycopg.Connection, team: Team, email: str, role: str, hours: int
) -> None:
    with (
        as_role(db, "authenticated", team.owner),
        expect_error(db, errors.InvalidParameterValue),
    ):
        _create(db, team.tenant, email=email, role=role, hours=hours)


def test_active_member_cannot_be_invited_again(db: psycopg.Connection, team: Team) -> None:
    operator_email = str(
        _one(db, "select email from users where auth_user_id = %s", (team.operator,))
    )
    with as_role(db, "authenticated", team.owner), expect_error(db, errors.UniqueViolation):
        _create(db, team.tenant, email=operator_email)


def test_reinvite_replaces_previous_pending_link(db: psycopg.Connection, team: Team) -> None:
    first = _invite(db, team.owner, team.tenant, role="operator")
    second = _invite(db, team.owner, team.tenant, role="viewer")

    assert _inspect(db, first.token_hash)[0] == "expired"
    assert _inspect(db, second.token_hash) == (
        "valid",
        "테스트 보안팀",
        "홍길동 컨설턴트",
        INVITEE_EMAIL,
        "viewer",
    )


# --- 조회 ----------------------------------------------------------------------------------


def test_inspect_reveals_nothing_for_unknown_token(db: psycopg.Connection, team: Team) -> None:
    _invite(db, team.owner, team.tenant)
    assert _inspect(db, hash_invitation_token("forged", SALT)) == (
        "invalid",
        None,
        None,
        None,
        None,
    )


# --- 수락 ----------------------------------------------------------------------------------


def test_invitee_accepts_once_and_joins_workspace(db: psycopg.Connection, team: Team) -> None:
    invite = _invite(db, team.owner, team.tenant)
    invitee = _auth_user(db, INVITEE_EMAIL.upper())

    assert _accept(db, invitee, invite.token_hash) == "accepted"
    row = db.execute(
        "select u.status::text, u.auth_user_id, i.used_at is not null "
        "from invitations i join users u on u.id = i.user_id where i.id = %s",
        (invite.invitation_id,),
    ).fetchone()
    assert row == ("active", invitee, True)

    # 수락 후에는 RLS 로 자기 워크스페이스를 볼 수 있다
    with as_role(db, "authenticated", invitee):
        assert _count(db, "select count(*) from tenants where id = %s", (team.tenant,)) == 1

    # 같은 링크는 다시 쓸 수 없다
    assert _accept(db, invitee, invite.token_hash) == "used"
    assert _inspect(db, invite.token_hash)[0] == "used"


def test_expired_invitation_is_rejected(db: psycopg.Connection, team: Team) -> None:
    invite = _invite(db, team.owner, team.tenant)
    db.execute(
        "update invitations set created_at = now() - interval '2 hours', "
        "expires_at = now() - interval '1 second' where id = %s",
        (invite.invitation_id,),
    )
    invitee = _auth_user(db, INVITEE_EMAIL)

    assert _inspect(db, invite.token_hash)[0] == "expired"
    assert _accept(db, invitee, invite.token_hash) == "expired"
    assert (
        _one(db, "select status::text from users where email = %s", (INVITEE_EMAIL,)) == "invited"
    )


def test_invitation_valid_until_one_second_before_expiry(
    db: psycopg.Connection, team: Team
) -> None:
    invite = _invite(db, team.owner, team.tenant)
    db.execute(
        "update invitations set created_at = now() - interval '2 hours', "
        "expires_at = now() + interval '1 second' where id = %s",
        (invite.invitation_id,),
    )
    assert _inspect(db, invite.token_hash)[0] == "valid"


def test_link_cannot_be_used_by_a_different_email(db: psycopg.Connection, team: Team) -> None:
    invite = _invite(db, team.owner, team.tenant)
    intruder = _auth_user(db, "intruder@example.com")

    assert _accept(db, intruder, invite.token_hash) == "email_mismatch"
    assert _inspect(db, invite.token_hash)[0] == "valid"
    with as_role(db, "authenticated", intruder):
        assert _count(db, "select count(*) from tenants") == 0


def test_forged_token_is_invalid(db: psycopg.Connection, team: Team) -> None:
    _invite(db, team.owner, team.tenant)
    invitee = _auth_user(db, INVITEE_EMAIL)
    assert _accept(db, invitee, hashlib.sha256(b"forged").hexdigest()) == "invalid"


def test_anon_cannot_accept(db: psycopg.Connection, team: Team) -> None:
    invite = _invite(db, team.owner, team.tenant)
    with as_role(db, "anon"), expect_error(db, errors.InsufficientPrivilege):
        db.execute("select public.accept_invitation(%s)", (invite.token_hash,))


# --- 철회 ----------------------------------------------------------------------------------


def test_owner_revokes_pending_invitation(db: psycopg.Connection, team: Team) -> None:
    invite = _invite(db, team.owner, team.tenant)
    with as_role(db, "authenticated", team.owner):
        db.execute("select public.revoke_invitation(%s)", (invite.invitation_id,))

    invitee = _auth_user(db, INVITEE_EMAIL)
    assert _inspect(db, invite.token_hash)[0] == "expired"
    assert _accept(db, invitee, invite.token_hash) == "expired"


@pytest.mark.parametrize("actor", ["operator", "other_owner"])
def test_only_tenant_owner_can_revoke(db: psycopg.Connection, team: Team, actor: str) -> None:
    invite = _invite(db, team.owner, team.tenant)
    with (
        as_role(db, "authenticated", getattr(team, actor)),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        db.execute("select public.revoke_invitation(%s)", (invite.invitation_id,))
    assert _inspect(db, invite.token_hash)[0] == "valid"


def test_used_invitation_cannot_be_revoked(db: psycopg.Connection, team: Team) -> None:
    invite = _invite(db, team.owner, team.tenant)
    _accept(db, _auth_user(db, INVITEE_EMAIL), invite.token_hash)
    with (
        as_role(db, "authenticated", team.owner),
        expect_error(db, errors.InsufficientPrivilege),
    ):
        db.execute("select public.revoke_invitation(%s)", (invite.invitation_id,))


# --- 동시 수락 -------------------------------------------------------------------------------


@pytest.fixture
def committed_invite(database_url: str) -> Iterator[tuple[str, uuid.UUID]]:
    """동시성 검증용: 다른 연결에서 보이도록 커밋된 초대를 만든다(일회용 DB 이므로 정리 불필요)."""
    email = f"race-{secrets.token_hex(4)}@example.com"
    with psycopg.connect(database_url) as conn:
        tenant = _new_id(conn, "insert into tenants (name) values ('동시성 테스트') returning id")
        owner = _member(conn, tenant, "owner")
        invite = _invite(conn, owner, tenant, email=email)
        invitee = _auth_user(conn, email)
        conn.commit()
    yield invite.token_hash, invitee


def test_concurrent_accepts_only_one_succeeds(
    database_url: str, committed_invite: tuple[str, uuid.UUID]
) -> None:
    token_hash, invitee = committed_invite
    results: list[str] = []

    with psycopg.connect(database_url) as first, psycopg.connect(database_url) as second:
        results.append(_accept(first, invitee, token_hash))  # 행 잠금을 쥔 채 커밋 전

        def accept_in_parallel() -> None:
            results.append(_accept(second, invitee, token_hash))
            second.commit()

        worker = threading.Thread(target=accept_in_parallel)
        worker.start()
        worker.join(timeout=1)
        assert worker.is_alive(), "두 번째 수락은 첫 번째 트랜잭션이 끝날 때까지 기다려야 한다"
        first.commit()
        worker.join(timeout=10)

    assert results == ["accepted", "used"]


# --- 소유자 프로비저닝 -------------------------------------------------------------------------


def test_hash_invitation_token_matches_sha256_of_token_and_salt() -> None:
    assert hash_invitation_token("abc", "salt") == hashlib.sha256(b"abcsalt").hexdigest()


def test_provision_owner_creates_workspace_and_single_use_link(db: psycopg.Connection) -> None:
    result = provision_owner(
        db,
        tenant_name=" 테스트 보안팀 ",
        owner_name="홍길동",
        owner_email="Owner@Example.com",
        salt=SALT,
        app_url="https://vuln.example.com/",
    )

    owner = db.execute(
        "select t.name, u.role::text, u.status::text, u.email from users u "
        "join tenants t on t.id = u.tenant_id where u.id = %s",
        (result.owner_user_id,),
    ).fetchone()
    assert owner == ("테스트 보안팀", "owner", "active", "owner@example.com")
    assert (
        _count(
            db,
            "select count(*) from risk_scoring_policies where tenant_id = %s",
            (result.tenant_id,),
        )
        == 1
    )

    url = urlsplit(result.invite_url)
    assert (url.scheme, url.netloc, url.path) == ("https", "vuln.example.com", "/auth/verify")
    token_hash = hash_invitation_token(parse_qs(url.query)["token"][0], SALT)
    assert _inspect(db, token_hash)[0] == "valid"

    owner_auth = _auth_user(db, "owner@example.com")
    assert _accept(db, owner_auth, token_hash) == "accepted"
    # 연결된 소유자는 바로 팀원을 초대할 수 있다
    _invite(db, owner_auth, uuid.UUID(result.tenant_id))

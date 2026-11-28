-- 초대 온보딩: 1회용 만료형 초대 발급·철회·조회·수락
--
-- 흐름
--   1. owner 가 create_invitation() 으로 팀원을 초대한다. 서버는 원본 토큰을 만들고 해시만 넘긴다.
--   2. 초대받은 사람이 링크를 열면 inspect_invitation() 으로 상태를 확인한다(비로그인 허용, 유효할 때만 최소 정보 반환).
--   3. Supabase Auth 매직 링크로 로그인한 뒤 accept_invitation() 이 토큰과 로그인 이메일을 함께 검증하고
--      사용자 행을 auth 계정에 연결·활성화한다. 같은 토큰은 한 번만 수락된다(행 잠금).
-- 시각 비교는 모두 DB 서버 시각(now())으로 한다.

-- 철회·재발급 시 expires_at 을 now() 로 당기므로, 같은 트랜잭션에서도 허용되도록 제약을 완화한다.
alter table public.invitations drop constraint invitations_expiry_after_creation;
alter table public.invitations add constraint invitations_expiry_not_before_creation
  check (expires_at >= created_at);

create index invitations_pending_idx on public.invitations (user_id) where used_at is null;

-- ---------------------------------------------------------------------------
-- 초대 발급 (owner)
-- ---------------------------------------------------------------------------
create function public.create_invitation(
  p_tenant_id uuid,
  p_email text,
  p_name text,
  p_role public.user_role,
  p_token_hash text,
  p_valid_hours int
)
returns table (invitation_id uuid, expires_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_email text := lower(btrim(coalesce(p_email, '')));
  v_name text := btrim(coalesce(p_name, ''));
  v_user public.users%rowtype;
  v_invitation_id uuid;
  v_expires_at timestamptz;
begin
  if not private.has_tenant_role(p_tenant_id, array['owner']::public.user_role[]) then
    raise exception '팀원을 초대할 권한이 없습니다' using errcode = 'insufficient_privilege';
  end if;
  if p_role is null or p_role not in ('operator', 'viewer') then
    raise exception '초대 역할은 operator 또는 viewer 여야 합니다' using errcode = 'invalid_parameter_value';
  end if;
  if p_valid_hours is null or p_valid_hours not between 1 and 72 then
    raise exception '유효기간은 1~72시간이어야 합니다' using errcode = 'invalid_parameter_value';
  end if;
  if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' or length(v_email) > 255 then
    raise exception '이메일 형식이 올바르지 않습니다' using errcode = 'invalid_parameter_value';
  end if;
  if length(v_name) = 0 or length(v_name) > 100 then
    raise exception '이름은 1~100자여야 합니다' using errcode = 'invalid_parameter_value';
  end if;

  select u.* into v_user
  from public.users u
  where u.tenant_id = p_tenant_id and lower(u.email) = v_email
  for update;

  if v_user.id is null then
    insert into public.users (tenant_id, email, name, role, status)
    values (p_tenant_id, v_email, v_name, p_role, 'invited')
    returning * into v_user;
  elsif v_user.status = 'invited' then
    update public.users set name = v_name, role = p_role where id = v_user.id;
  else
    raise exception '이미 등록된 사용자입니다' using errcode = 'unique_violation';
  end if;

  -- 같은 사용자에게 남아 있던 미사용 초대는 즉시 무효화
  update public.invitations i
  set expires_at = greatest(now(), i.created_at)
  where i.user_id = v_user.id and i.used_at is null and i.expires_at > now();

  v_expires_at := now() + make_interval(hours => p_valid_hours);
  insert into public.invitations (token_hash, tenant_id, user_id, expires_at)
  values (p_token_hash, p_tenant_id, v_user.id, v_expires_at)
  returning id into v_invitation_id;

  return query select v_invitation_id, v_expires_at;
end;
$$;

-- ---------------------------------------------------------------------------
-- 초대 철회 (owner, 미사용 초대만)
-- ---------------------------------------------------------------------------
create function public.revoke_invitation(p_invitation_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_updated int;
begin
  update public.invitations i
  set expires_at = greatest(now(), i.created_at)
  where i.id = p_invitation_id
    and i.used_at is null
    and private.has_tenant_role(i.tenant_id, array['owner']::public.user_role[]);
  get diagnostics v_updated = row_count;

  if v_updated = 0 then
    raise exception '철회할 수 있는 초대가 없거나 권한이 없습니다' using errcode = 'insufficient_privilege';
  end if;
end;
$$;

-- ---------------------------------------------------------------------------
-- 초대 상태 조회 (공개). 유효한 경우에만 최소 정보를 돌려준다.
-- status: valid | invalid | expired | used
-- ---------------------------------------------------------------------------
create function public.inspect_invitation(p_token_hash text)
returns table (status text, tenant_name text, user_name text, email text, role public.user_role)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_invitation public.invitations%rowtype;
begin
  select i.* into v_invitation from public.invitations i where i.token_hash = p_token_hash;

  if v_invitation.id is null then
    return query select 'invalid'::text, null::text, null::text, null::text, null::public.user_role;
  elsif v_invitation.used_at is not null then
    return query select 'used'::text, null::text, null::text, null::text, null::public.user_role;
  elsif v_invitation.expires_at <= now() then
    return query select 'expired'::text, null::text, null::text, null::text, null::public.user_role;
  else
    return query
      select 'valid'::text, t.name::text, u.name::text, u.email::text, u.role
      from public.users u
      join public.tenants t on t.id = u.tenant_id
      where u.id = v_invitation.user_id;
  end if;
end;
$$;

-- ---------------------------------------------------------------------------
-- 초대 수락 (매직 링크로 로그인한 사용자)
-- status: accepted | invalid | expired | used | email_mismatch
-- ---------------------------------------------------------------------------
create function public.accept_invitation(p_token_hash text)
returns table (status text, tenant_id uuid)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := (select auth.uid());
  v_auth_email text;
  v_invitation public.invitations%rowtype;
  v_user public.users%rowtype;
begin
  if v_uid is null then
    raise exception '로그인이 필요합니다' using errcode = 'insufficient_privilege';
  end if;

  -- 동시에 같은 토큰을 수락해도 한 요청만 통과하도록 행을 잠근다
  select i.* into v_invitation
  from public.invitations i
  where i.token_hash = p_token_hash
  for update;

  if v_invitation.id is null then
    return query select 'invalid'::text, null::uuid;
    return;
  elsif v_invitation.used_at is not null then
    return query select 'used'::text, null::uuid;
    return;
  elsif v_invitation.expires_at <= now() then
    return query select 'expired'::text, null::uuid;
    return;
  end if;

  select u.* into v_user from public.users u where u.id = v_invitation.user_id for update;
  select lower(a.email) into v_auth_email from auth.users a where a.id = v_uid;

  -- 토큰만으로는 부족하다: 초대받은 이메일로 로그인한 계정이어야 한다
  if v_auth_email is null
     or v_auth_email <> lower(v_user.email)
     or (v_user.auth_user_id is not null and v_user.auth_user_id <> v_uid) then
    return query select 'email_mismatch'::text, null::uuid;
    return;
  end if;

  if v_user.status = 'suspended' then
    return query select 'invalid'::text, null::uuid;
    return;
  end if;

  update public.invitations set used_at = now() where id = v_invitation.id;
  update public.users set status = 'active', auth_user_id = v_uid where id = v_user.id;

  return query select 'accepted'::text, v_invitation.tenant_id;
end;
$$;

revoke execute on function public.create_invitation(uuid, text, text, public.user_role, text, int) from public, anon, authenticated, service_role;
revoke execute on function public.revoke_invitation(uuid) from public, anon, authenticated, service_role;
revoke execute on function public.inspect_invitation(text) from public, anon, authenticated, service_role;
revoke execute on function public.accept_invitation(text) from public, anon, authenticated, service_role;

grant execute on function public.create_invitation(uuid, text, text, public.user_role, text, int) to authenticated;
grant execute on function public.revoke_invitation(uuid) to authenticated;
grant execute on function public.inspect_invitation(text) to anon, authenticated;
grant execute on function public.accept_invitation(text) to authenticated;

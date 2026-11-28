-- 진단 인프라 통합 데이터 기반: 멀티테넌트 스키마, RLS, 감사 로그 불변성, 수동 판정 변경 함수
--
-- 접근 모델
--   * anon            : 어떤 테이블에도 접근 불가
--   * authenticated   : 소속 테넌트(활성 사용자) 데이터만 조회. 사용자 화면에서 바로 바꾸는 값만 RLS로 쓰기 허용
--                       (테넌트 설정·팀원·위험도 정책 = owner, 자산 중요도 = owner/operator)
--                       판정 변경은 public.apply_item_override() 로만 가능
--   * service_role    : 백엔드 파이프라인(업로드·파싱·조판·초대 발급). RLS 우회, 감사 로그는 추가·조회만
-- 시각은 모두 timestamptz 로 저장한다(표시는 Asia/Seoul).

create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 열거형
-- ---------------------------------------------------------------------------
create type public.user_role as enum ('owner', 'operator', 'viewer');
create type public.user_status as enum ('active', 'invited', 'suspended');
create type public.os_family as enum ('linux', 'windows');
create type public.assessment_status as enum ('queued', 'parsing', 'scoring', 'rendering', 'completed', 'failed');
create type public.parsing_status as enum ('success', 'partial_error', 'failed');
create type public.compliance_risk_level as enum ('high', 'medium', 'low');
create type public.compliance_category as enum (
  'account_management',
  'directory_file_management',
  'service_management',
  'patch_management',
  'log_management'
);
create type public.item_status as enum ('good', 'vulnerable', 'na');
create type public.report_type as enum ('detailed', 'summary', 'risk_plan');
create type public.report_format as enum ('docx', 'pdf');

-- ---------------------------------------------------------------------------
-- 테이블
-- 테넌트 종속 테이블은 모두 tenant_id 를 갖고, 부모와 (id, tenant_id) 복합 외래키로 묶어
-- 다른 테넌트의 진단 차수·자산·사용자를 참조하는 행 자체를 만들 수 없게 한다.
-- ---------------------------------------------------------------------------
create table public.tenants (
  id uuid primary key default gen_random_uuid(),
  name varchar(100) not null check (length(btrim(name)) > 0),
  zero_retention_enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.users (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  -- Supabase Auth 계정. 초대만 된 사용자는 아직 계정이 없으므로 null 허용
  auth_user_id uuid references auth.users (id) on delete set null,
  email varchar(255) not null check (position('@' in email) > 1),
  name varchar(100) not null check (length(btrim(name)) > 0),
  role public.user_role not null default 'operator',
  status public.user_status not null default 'invited',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint uq_tenant_email unique (tenant_id, email),
  constraint uq_tenant_auth_user unique (tenant_id, auth_user_id),
  constraint uq_users_id_tenant unique (id, tenant_id)
);
create index users_auth_user_id_idx on public.users (auth_user_id);

create table public.invitations (
  id uuid primary key default gen_random_uuid(),
  token_hash char(64) not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  user_id uuid not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now(),
  constraint invitations_user_fk foreign key (user_id, tenant_id)
    references public.users (id, tenant_id) on delete cascade,
  constraint invitations_expiry_after_creation check (expires_at > created_at)
);
create index invitations_tenant_id_idx on public.invitations (tenant_id);
create index invitations_user_id_tenant_id_idx on public.invitations (user_id, tenant_id);

create table public.risk_scoring_policies (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null unique references public.tenants (id) on delete cascade,
  confidentiality_weight numeric(3, 2) not null default 1.00 check (confidentiality_weight > 0),
  integrity_weight numeric(3, 2) not null default 1.00 check (integrity_weight > 0),
  availability_weight numeric(3, 2) not null default 1.00 check (availability_weight > 0),
  critical_threshold int not null default 15,
  warning_threshold int not null default 8,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint risk_thresholds_ordered check (0 < warning_threshold and warning_threshold < critical_threshold)
);

create table public.assets (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  hostname varchar(255) not null check (length(btrim(hostname)) > 0),
  ip_address varchar(45),
  os_type public.os_family not null,
  os_version varchar(100),
  confidentiality_score int not null default 2 check (confidentiality_score between 1 and 3),
  integrity_score int not null default 2 check (integrity_score between 1 and 3),
  availability_score int not null default 2 check (availability_score between 1 and 3),
  last_assessed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint uq_tenant_hostname unique (tenant_id, hostname),
  constraint uq_assets_id_tenant unique (id, tenant_id)
);

create table public.assessment_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  title varchar(200) not null check (length(btrim(title)) > 0),
  status public.assessment_status not null default 'queued',
  raw_archive_sha256 char(64) check (raw_archive_sha256 ~ '^[0-9a-f]{64}$'),
  total_assets int not null default 0 check (total_assets >= 0),
  vulnerable_items_count int not null default 0 check (vulnerable_items_count >= 0),
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint uq_runs_id_tenant unique (id, tenant_id)
);
create index assessment_runs_tenant_created_idx on public.assessment_runs (tenant_id, created_at desc);

create table public.diagnostic_logs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  assessment_run_id uuid not null,
  asset_id uuid,
  file_name varchar(255) not null,
  file_size_bytes bigint not null check (file_size_bytes >= 0),
  storage_path varchar(500),
  parse_status public.parsing_status not null default 'success',
  quarantined_error_lines int not null default 0 check (quarantined_error_lines >= 0),
  error_details jsonb,
  created_at timestamptz not null default now(),
  constraint diagnostic_logs_run_fk foreign key (assessment_run_id, tenant_id)
    references public.assessment_runs (id, tenant_id) on delete cascade,
  constraint diagnostic_logs_asset_fk foreign key (asset_id, tenant_id)
    references public.assets (id, tenant_id) on delete set null (asset_id)
);
create index diagnostic_logs_tenant_id_idx on public.diagnostic_logs (tenant_id);
create index diagnostic_logs_run_idx on public.diagnostic_logs (assessment_run_id, tenant_id);
create index diagnostic_logs_asset_idx on public.diagnostic_logs (asset_id, tenant_id);

-- 테넌트 공통 국가 표준 마스터(KISA 주요정보통신기반시설 기술적 취약점 분석·평가 기준)
create table public.compliance_guidelines (
  item_code varchar(20) primary key check (item_code ~ '^[A-Z]{1,3}-[0-9]{2,3}$'),
  category public.compliance_category not null,
  name varchar(255) not null,
  risk_level public.compliance_risk_level not null,
  standard_criteria text not null,
  good_condition text not null,
  vulnerable_condition text not null,
  remediation_guide text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.inspection_item_results (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  assessment_run_id uuid not null,
  asset_id uuid not null,
  item_code varchar(20) not null references public.compliance_guidelines (item_code),
  auto_status public.item_status not null,
  final_status public.item_status not null,
  stdout_snippet text,
  raw_log_start_line int check (raw_log_start_line > 0),
  raw_log_end_line int,
  calculated_risk_score numeric(5, 2) not null default 0.00 check (calculated_risk_score >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint uq_run_asset_item unique (assessment_run_id, asset_id, item_code),
  constraint uq_results_id_tenant unique (id, tenant_id),
  constraint results_run_fk foreign key (assessment_run_id, tenant_id)
    references public.assessment_runs (id, tenant_id) on delete cascade,
  constraint results_asset_fk foreign key (asset_id, tenant_id)
    references public.assets (id, tenant_id) on delete cascade,
  constraint results_line_range check (raw_log_end_line is null or raw_log_end_line >= raw_log_start_line)
);
create index inspection_results_run_status_idx on public.inspection_item_results (assessment_run_id, final_status);
create index inspection_results_asset_item_idx on public.inspection_item_results (asset_id, item_code);
create index inspection_results_tenant_id_idx on public.inspection_item_results (tenant_id);
create index inspection_results_item_code_idx on public.inspection_item_results (item_code);

-- 감사 로그는 영구 보관한다. 부모 삭제로 지워지지 않도록 restrict 로 두고, 아래 트리거가 수정·삭제를 막는다.
-- (감사 로그가 있는 판정 결과·진단 차수·테넌트는 삭제되지 않는다.)
create table public.override_audit_logs (
  id uuid primary key default gen_random_uuid(),
  inspection_item_result_id uuid not null,
  tenant_id uuid not null references public.tenants (id) on delete restrict,
  actor_user_id uuid not null,
  previous_status public.item_status not null,
  new_status public.item_status not null,
  override_reason text not null check (length(btrim(override_reason)) >= 5),
  created_at timestamptz not null default now(),
  constraint audit_result_fk foreign key (inspection_item_result_id, tenant_id)
    references public.inspection_item_results (id, tenant_id) on delete restrict,
  constraint audit_actor_fk foreign key (actor_user_id, tenant_id)
    references public.users (id, tenant_id) on delete restrict,
  constraint audit_status_changed check (previous_status <> new_status)
);
create index override_audit_result_created_idx on public.override_audit_logs (inspection_item_result_id, created_at desc);
create index override_audit_tenant_created_idx on public.override_audit_logs (tenant_id, created_at desc);
create index override_audit_actor_idx on public.override_audit_logs (actor_user_id, tenant_id);

create table public.generated_reports (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  assessment_run_id uuid not null,
  report_type public.report_type not null,
  format public.report_format not null,
  storage_path varchar(500) not null,
  file_size_bytes bigint not null check (file_size_bytes >= 0),
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  constraint uq_run_report_format unique (assessment_run_id, report_type, format),
  constraint reports_run_fk foreign key (assessment_run_id, tenant_id)
    references public.assessment_runs (id, tenant_id) on delete cascade
);
create index generated_reports_tenant_id_idx on public.generated_reports (tenant_id);

-- ---------------------------------------------------------------------------
-- 트리거: updated_at 갱신, 감사 로그 불변성
-- ---------------------------------------------------------------------------
create function private.set_updated_at() returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

do $$
declare
  t text;
begin
  foreach t in array array[
    'tenants', 'users', 'risk_scoring_policies', 'assets', 'assessment_runs',
    'compliance_guidelines', 'inspection_item_results'
  ] loop
    execute format(
      'create trigger set_updated_at before update on public.%I for each row execute function private.set_updated_at()',
      t
    );
  end loop;
end;
$$;

create function private.reject_audit_log_mutation() returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'override_audit_logs is append-only: % is not allowed', tg_op
    using errcode = 'insufficient_privilege';
end;
$$;

create trigger override_audit_logs_no_update_delete
  before update or delete on public.override_audit_logs
  for each row execute function private.reject_audit_log_mutation();
create trigger override_audit_logs_no_truncate
  before truncate on public.override_audit_logs
  for each statement execute function private.reject_audit_log_mutation();

-- ---------------------------------------------------------------------------
-- RLS 헬퍼 (private 스키마, 노출되지 않음)
-- users 테이블 RLS 를 다시 타지 않도록 security definer 로 소속을 확인한다. 활성(active) 사용자만 인정.
-- ---------------------------------------------------------------------------
create function private.has_tenant_role(p_tenant_id uuid, p_roles public.user_role[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.users u
    where u.tenant_id = p_tenant_id
      and u.auth_user_id = (select auth.uid())
      and u.status = 'active'
      and u.role = any (p_roles)
  );
$$;

create function private.is_tenant_member(p_tenant_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.has_tenant_role(p_tenant_id, array['owner', 'operator', 'viewer']::public.user_role[]);
$$;

revoke execute on function private.has_tenant_role(uuid, public.user_role[]) from public, anon, authenticated;
revoke execute on function private.is_tenant_member(uuid) from public, anon, authenticated;
grant execute on function private.has_tenant_role(uuid, public.user_role[]) to authenticated;
grant execute on function private.is_tenant_member(uuid) to authenticated;
revoke execute on function private.set_updated_at() from public, anon, authenticated;
revoke execute on function private.reject_audit_log_mutation() from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 권한: 기본 권한을 모두 회수하고 필요한 것만 부여
-- ---------------------------------------------------------------------------
do $$
declare
  t text;
begin
  foreach t in array array[
    'tenants', 'users', 'invitations', 'risk_scoring_policies', 'assets', 'assessment_runs',
    'diagnostic_logs', 'compliance_guidelines', 'inspection_item_results', 'override_audit_logs',
    'generated_reports'
  ] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on table public.%I from public, anon, authenticated, service_role', t);
  end loop;
end;
$$;

-- service_role: 백엔드 파이프라인. 감사 로그는 추가·조회만
grant select, insert, update, delete on
  public.tenants, public.users, public.invitations, public.risk_scoring_policies, public.assets,
  public.assessment_runs, public.diagnostic_logs, public.compliance_guidelines,
  public.inspection_item_results, public.generated_reports
  to service_role;
grant select, insert on public.override_audit_logs to service_role;

-- authenticated: 조회 + 화면에서 직접 바꾸는 값만
grant select on
  public.tenants, public.users, public.invitations, public.risk_scoring_policies, public.assets,
  public.assessment_runs, public.diagnostic_logs, public.compliance_guidelines,
  public.inspection_item_results, public.override_audit_logs, public.generated_reports
  to authenticated;
grant update (name, zero_retention_enabled) on public.tenants to authenticated;
grant insert (tenant_id, email, name, role, status) on public.users to authenticated;
grant update (name, role, status) on public.users to authenticated;
grant delete on public.users to authenticated;
grant insert (tenant_id, confidentiality_weight, integrity_weight, availability_weight, critical_threshold, warning_threshold)
  on public.risk_scoring_policies to authenticated;
grant update (confidentiality_weight, integrity_weight, availability_weight, critical_threshold, warning_threshold)
  on public.risk_scoring_policies to authenticated;
grant update (confidentiality_score, integrity_score, availability_score) on public.assets to authenticated;

-- ---------------------------------------------------------------------------
-- RLS 정책 (authenticated 대상)
-- ---------------------------------------------------------------------------
create policy tenants_select_member on public.tenants
  for select to authenticated using ((select private.is_tenant_member(id)));
create policy tenants_update_owner on public.tenants
  for update to authenticated
  using ((select private.has_tenant_role(id, array['owner']::public.user_role[])))
  with check ((select private.has_tenant_role(id, array['owner']::public.user_role[])));

create policy users_select_member on public.users
  for select to authenticated using ((select private.is_tenant_member(tenant_id)));
create policy users_insert_owner on public.users
  for insert to authenticated
  with check ((select private.has_tenant_role(tenant_id, array['owner']::public.user_role[])));
create policy users_update_owner on public.users
  for update to authenticated
  using ((select private.has_tenant_role(tenant_id, array['owner']::public.user_role[])))
  with check ((select private.has_tenant_role(tenant_id, array['owner']::public.user_role[])));
create policy users_delete_owner on public.users
  for delete to authenticated
  using ((select private.has_tenant_role(tenant_id, array['owner']::public.user_role[])));

-- 초대 토큰 해시는 owner 만 조회
create policy invitations_select_owner on public.invitations
  for select to authenticated
  using ((select private.has_tenant_role(tenant_id, array['owner']::public.user_role[])));

create policy risk_policies_select_member on public.risk_scoring_policies
  for select to authenticated using ((select private.is_tenant_member(tenant_id)));
create policy risk_policies_insert_owner on public.risk_scoring_policies
  for insert to authenticated
  with check ((select private.has_tenant_role(tenant_id, array['owner']::public.user_role[])));
create policy risk_policies_update_owner on public.risk_scoring_policies
  for update to authenticated
  using ((select private.has_tenant_role(tenant_id, array['owner']::public.user_role[])))
  with check ((select private.has_tenant_role(tenant_id, array['owner']::public.user_role[])));

create policy assets_select_member on public.assets
  for select to authenticated using ((select private.is_tenant_member(tenant_id)));
create policy assets_update_operator on public.assets
  for update to authenticated
  using ((select private.has_tenant_role(tenant_id, array['owner', 'operator']::public.user_role[])))
  with check ((select private.has_tenant_role(tenant_id, array['owner', 'operator']::public.user_role[])));

create policy assessment_runs_select_member on public.assessment_runs
  for select to authenticated using ((select private.is_tenant_member(tenant_id)));
create policy diagnostic_logs_select_member on public.diagnostic_logs
  for select to authenticated using ((select private.is_tenant_member(tenant_id)));
create policy inspection_results_select_member on public.inspection_item_results
  for select to authenticated using ((select private.is_tenant_member(tenant_id)));
create policy override_audit_select_member on public.override_audit_logs
  for select to authenticated using ((select private.is_tenant_member(tenant_id)));
create policy generated_reports_select_member on public.generated_reports
  for select to authenticated using ((select private.is_tenant_member(tenant_id)));

-- 국가 표준 기준은 모든 로그인 사용자가 읽는 공용 참조 데이터(쓰기는 마이그레이션·service_role 만)
create policy compliance_guidelines_select_authenticated on public.compliance_guidelines
  for select to authenticated using (true);

-- ---------------------------------------------------------------------------
-- 수동 판정 변경: 결과 갱신과 감사 로그 추가를 한 트랜잭션에서 수행
-- 호출자 신원은 인자가 아니라 auth.uid() 로 확인한다.
-- ---------------------------------------------------------------------------
create function public.apply_item_override(
  p_item_result_id uuid,
  p_new_status public.item_status,
  p_reason text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_result public.inspection_item_results%rowtype;
  v_actor_id uuid;
begin
  if (select auth.uid()) is null then
    raise exception '로그인이 필요합니다' using errcode = 'insufficient_privilege';
  end if;

  if p_new_status is null then
    raise exception '변경할 판정 값을 지정해야 합니다' using errcode = 'invalid_parameter_value';
  end if;

  if length(btrim(coalesce(p_reason, ''))) < 5 then
    raise exception '변경 사유를 5자 이상 입력해야 합니다' using errcode = 'invalid_parameter_value';
  end if;

  select r.* into v_result
  from public.inspection_item_results r
  where r.id = p_item_result_id
  for update;

  select u.id into v_actor_id
  from public.users u
  where v_result.id is not null
    and u.tenant_id = v_result.tenant_id
    and u.auth_user_id = (select auth.uid())
    and u.status = 'active'
    and u.role in ('owner', 'operator');

  -- 다른 테넌트 항목의 존재 여부를 드러내지 않도록 "없음"과 "권한 없음"을 같은 오류로 처리
  if v_actor_id is null then
    raise exception '항목이 없거나 판정을 변경할 권한이 없습니다' using errcode = 'insufficient_privilege';
  end if;

  if v_result.final_status = p_new_status then
    return;
  end if;

  update public.inspection_item_results
  set final_status = p_new_status
  where id = v_result.id;

  insert into public.override_audit_logs (
    inspection_item_result_id, tenant_id, actor_user_id, previous_status, new_status, override_reason
  ) values (
    v_result.id, v_result.tenant_id, v_actor_id, v_result.final_status, p_new_status, btrim(p_reason)
  );
end;
$$;

revoke execute on function public.apply_item_override(uuid, public.item_status, text) from public, anon, authenticated, service_role;
grant execute on function public.apply_item_override(uuid, public.item_status, text) to authenticated;

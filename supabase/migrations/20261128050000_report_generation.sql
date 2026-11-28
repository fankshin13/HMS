-- 3종 보고서 조판 대기열, 보고서 저장소, 원본 로그 영구 파기(제로 리텐션)
--
-- 조판 상태는 진단 차수 상태(assessment_runs.status)와 분리해 report_jobs 에 둔다.
-- 조판이 실패해도 분석 결과 화면은 그대로 '분석 완료'로 남고, 보고서만 재시도할 수 있다.
-- 조판은 백엔드 워커(service role / DB 직접 접속)가 처리하고, 사용자는 요청·조회만 한다.

create type public.report_job_status as enum ('queued', 'rendering', 'completed', 'failed');

create table public.report_jobs (
  assessment_run_id uuid primary key,
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  status public.report_job_status not null default 'queued',
  progress_percentage int not null default 0 check (progress_percentage between 0 and 100),
  current_step varchar(50) not null default 'queued',
  error_message varchar(1000),
  requested_by uuid,
  requested_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz,
  constraint report_jobs_run_fk foreign key (assessment_run_id, tenant_id)
    references public.assessment_runs (id, tenant_id) on delete cascade,
  constraint report_jobs_requester_fk foreign key (requested_by, tenant_id)
    references public.users (id, tenant_id) on delete set null (requested_by)
);
create index report_jobs_queue_idx on public.report_jobs (status, requested_at);
create index report_jobs_tenant_idx on public.report_jobs (tenant_id);

alter table public.report_jobs enable row level security;
revoke all on table public.report_jobs from public, anon, authenticated, service_role;
grant select on public.report_jobs to authenticated;
grant select, insert, update, delete on public.report_jobs to service_role;
create policy report_jobs_select_member on public.report_jobs
  for select to authenticated using ((select private.is_tenant_member(tenant_id)));

-- 원본 로그 파기 시각 (null 이면 아직 보관 중)
alter table public.assessment_runs add column raw_logs_purged_at timestamptz;

-- 원본 로그 파기 감사 기록 (추가·조회만)
-- trigger: manual(사용자가 다운로드 후 파기) | expiry(보존 기한이 지나 워커가 자동 파기, actor 없음)
create table public.purge_audit_logs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  assessment_run_id uuid not null,
  actor_user_id uuid,
  trigger varchar(20) not null default 'manual' check (trigger in ('manual', 'expiry')),
  purged_log_count int not null check (purged_log_count >= 0),
  purged_reports boolean not null default false,
  created_at timestamptz not null default now(),
  constraint purge_audit_run_fk foreign key (assessment_run_id, tenant_id)
    references public.assessment_runs (id, tenant_id) on delete cascade,
  constraint purge_audit_actor_fk foreign key (actor_user_id, tenant_id)
    references public.users (id, tenant_id),
  constraint purge_audit_actor_required check (trigger = 'expiry' or actor_user_id is not null)
);
create index purge_audit_run_idx on public.purge_audit_logs (assessment_run_id, created_at desc);
create index purge_audit_tenant_idx on public.purge_audit_logs (tenant_id);
create index purge_audit_actor_idx on public.purge_audit_logs (actor_user_id, tenant_id);

alter table public.purge_audit_logs enable row level security;
revoke all on table public.purge_audit_logs from public, anon, authenticated, service_role;
grant select on public.purge_audit_logs to authenticated;
grant select, insert on public.purge_audit_logs to service_role;
create policy purge_audit_select_member on public.purge_audit_logs
  for select to authenticated using ((select private.is_tenant_member(tenant_id)));

create trigger purge_audit_logs_no_update_delete
  before update or delete on public.purge_audit_logs
  for each row execute function private.reject_audit_log_mutation();
create trigger purge_audit_logs_no_truncate
  before truncate on public.purge_audit_logs
  for each statement execute function private.reject_audit_log_mutation();

create index generated_reports_expires_idx on public.generated_reports (expires_at);

-- ---------------------------------------------------------------------------
-- 보고서 저장소: reports/<tenant_id>/<assessment_run_id>/<report_type>.<format>
-- 쓰기는 워커(service role)만, 읽기는 테넌트 구성원 전체(viewer 포함), 삭제는 owner/operator.
-- ---------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'reports', 'reports', false, 104857600,
  array['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
)
on conflict (id) do nothing;

create policy reports_select_member on storage.objects
  for select to authenticated
  using (
    bucket_id = 'reports'
    and (select private.is_tenant_member(private.try_uuid((storage.foldername(name))[1])))
  );

create policy reports_delete_operator on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'reports'
    and (select private.has_tenant_role(
      private.try_uuid((storage.foldername(name))[1]),
      array['owner', 'operator']::public.user_role[]
    ))
  );

-- private.is_tenant_member 는 storage 정책에서 authenticated 로 호출된다
grant execute on function private.is_tenant_member(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- 조판 요청 (owner/operator). 멱등: 진행 중이면 그 상태를, 유효한 산출물 6개가 있으면 완료 상태를 돌려준다.
-- ---------------------------------------------------------------------------
create function public.request_report_generation(p_run_id uuid, p_force boolean default false)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_run public.assessment_runs%rowtype;
  v_actor_id uuid;
  v_job public.report_jobs%rowtype;
  v_valid int;
begin
  if (select auth.uid()) is null then
    raise exception '로그인이 필요합니다' using errcode = 'insufficient_privilege';
  end if;

  select r.* into v_run from public.assessment_runs r where r.id = p_run_id;
  select u.id into v_actor_id
  from public.users u
  where v_run.id is not null
    and u.tenant_id = v_run.tenant_id
    and u.auth_user_id = (select auth.uid())
    and u.status = 'active'
    and u.role in ('owner', 'operator');
  if v_actor_id is null then
    raise exception '진단 차수가 없거나 보고서를 생성할 권한이 없습니다' using errcode = 'insufficient_privilege';
  end if;
  if v_run.status <> 'completed' then
    raise exception '진단 분석이 완료되지 않아 보고서를 생성할 수 없습니다' using errcode = 'object_not_in_prerequisite_state';
  end if;

  select j.* into v_job from public.report_jobs j where j.assessment_run_id = p_run_id for update;

  if v_job.assessment_run_id is not null and v_job.status in ('queued', 'rendering') then
    return jsonb_build_object('assessment_run_id', p_run_id, 'status', v_job.status, 'dispatched', false);
  end if;

  select count(*) into v_valid
  from public.generated_reports g
  where g.assessment_run_id = p_run_id and g.expires_at > now();
  if not p_force and v_job.status = 'completed' and v_valid = 6 then
    return jsonb_build_object('assessment_run_id', p_run_id, 'status', 'completed', 'dispatched', false);
  end if;

  insert into public.report_jobs as j (
    assessment_run_id, tenant_id, status, progress_percentage, current_step, error_message,
    requested_by, requested_at, started_at, completed_at
  ) values (
    p_run_id, v_run.tenant_id, 'queued', 0, 'queued', null, v_actor_id, now(), null, null
  )
  on conflict (assessment_run_id) do update
  set status = 'queued', progress_percentage = 0, current_step = 'queued', error_message = null,
      requested_by = excluded.requested_by, requested_at = now(), started_at = null, completed_at = null;

  return jsonb_build_object('assessment_run_id', p_run_id, 'status', 'queued', 'dispatched', true);
end;
$$;

revoke execute on function public.request_report_generation(uuid, boolean) from public, anon, authenticated, service_role;
grant execute on function public.request_report_generation(uuid, boolean) to authenticated;

-- ---------------------------------------------------------------------------
-- 원본 로그 파기 기록 (owner/operator). 저장소 객체 삭제는 호출자가 먼저 수행한다
-- (Storage API 로 지운 뒤 이 함수로 참조 정리·감사 기록). 반복 호출해도 안전하다.
-- p_purge_reports: 보고서 레코드까지 지움(저장소 객체 삭제도 호출자가 먼저 수행).
-- ---------------------------------------------------------------------------
create function public.purge_raw_diagnostic_data(p_run_id uuid, p_purge_reports boolean default false)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_run public.assessment_runs%rowtype;
  v_actor_id uuid;
  v_count int;
  v_purged_at timestamptz;
begin
  if (select auth.uid()) is null then
    raise exception '로그인이 필요합니다' using errcode = 'insufficient_privilege';
  end if;

  select r.* into v_run from public.assessment_runs r where r.id = p_run_id for update;
  select u.id into v_actor_id
  from public.users u
  where v_run.id is not null
    and u.tenant_id = v_run.tenant_id
    and u.auth_user_id = (select auth.uid())
    and u.status = 'active'
    and u.role in ('owner', 'operator');
  if v_actor_id is null then
    raise exception '진단 차수가 없거나 원본을 파기할 권한이 없습니다' using errcode = 'insufficient_privilege';
  end if;

  update public.diagnostic_logs set storage_path = null
  where assessment_run_id = p_run_id and storage_path is not null;
  get diagnostics v_count = row_count;

  if p_purge_reports then
    delete from public.generated_reports where assessment_run_id = p_run_id;
    delete from public.report_jobs where assessment_run_id = p_run_id;
  end if;

  update public.assessment_runs
  set raw_logs_purged_at = coalesce(raw_logs_purged_at, now())
  where id = p_run_id
  returning raw_logs_purged_at into v_purged_at;

  insert into public.purge_audit_logs (tenant_id, assessment_run_id, actor_user_id, purged_log_count, purged_reports)
  values (v_run.tenant_id, p_run_id, v_actor_id, v_count, p_purge_reports);

  return jsonb_build_object(
    'assessment_run_id', p_run_id, 'purged_log_count', v_count, 'purged_at', v_purged_at
  );
end;
$$;

revoke execute on function public.purge_raw_diagnostic_data(uuid, boolean) from public, anon, authenticated, service_role;
grant execute on function public.purge_raw_diagnostic_data(uuid, boolean) to authenticated;

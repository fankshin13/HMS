-- 자산 중요도·위험도 정책 변경과 점수 재계산, 대시보드·자산 집계
--
-- 위험 점수는 판정 결과(inspection_item_results.calculated_risk_score)에 저장되므로, 자산 중요도(C·I·A)나
-- 테넌트 가중치가 바뀌면 다시 계산해야 한다. 직접 UPDATE 로 바꾸면 점수와 어긋나므로 화면에서의 변경은
-- 아래 함수로만 허용한다(이미 만든 보고서 파일은 만든 시점의 값을 유지한다).

-- 직접 쓰기 권한 회수 → 함수로만 변경
revoke update (confidentiality_score, integrity_score, availability_score) on public.assets from authenticated;
revoke insert (tenant_id, confidentiality_weight, integrity_weight, availability_weight, critical_threshold, warning_threshold)
  on public.risk_scoring_policies from authenticated;
revoke update (confidentiality_weight, integrity_weight, availability_weight, critical_threshold, warning_threshold)
  on public.risk_scoring_policies from authenticated;
drop policy assets_update_operator on public.assets;
drop policy risk_policies_insert_owner on public.risk_scoring_policies;
drop policy risk_policies_update_owner on public.risk_scoring_policies;

-- 가중치 범위: 0.50 ~ 3.00
alter table public.risk_scoring_policies
  add constraint risk_weights_range check (
    confidentiality_weight between 0.50 and 3.00
    and integrity_weight between 0.50 and 3.00
    and availability_weight between 0.50 and 3.00
  );

-- ---------------------------------------------------------------------------
-- 점수 재계산 (내부용). p_asset_id 가 있으면 그 자산만.
-- ---------------------------------------------------------------------------
create function private.recalculate_risk_scores(p_tenant_id uuid, p_asset_id uuid default null)
returns int
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_count int;
begin
  with weights as (
    select
      coalesce((select p.confidentiality_weight from public.risk_scoring_policies p where p.tenant_id = p_tenant_id), 1.00) as wc,
      coalesce((select p.integrity_weight from public.risk_scoring_policies p where p.tenant_id = p_tenant_id), 1.00) as wi,
      coalesce((select p.availability_weight from public.risk_scoring_policies p where p.tenant_id = p_tenant_id), 1.00) as wa
  )
  update public.inspection_item_results i
  set calculated_risk_score = private.compute_risk_score(
    i.final_status, g.risk_level,
    a.confidentiality_score, a.integrity_score, a.availability_score,
    w.wc, w.wi, w.wa
  )
  from public.assets a, public.compliance_guidelines g, weights w
  where i.asset_id = a.id
    and g.item_code = i.item_code
    and i.tenant_id = p_tenant_id
    and (p_asset_id is null or i.asset_id = p_asset_id);
  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

revoke execute on function private.recalculate_risk_scores(uuid, uuid) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 자산 중요도 변경 (owner/operator)
-- ---------------------------------------------------------------------------
create function public.update_asset_importance(
  p_asset_id uuid,
  p_confidentiality int,
  p_integrity int,
  p_availability int
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_asset public.assets%rowtype;
  v_count int;
begin
  if (select auth.uid()) is null then
    raise exception '로그인이 필요합니다' using errcode = 'insufficient_privilege';
  end if;
  select a.* into v_asset from public.assets a where a.id = p_asset_id for update;
  if v_asset.id is null
     or not private.has_tenant_role(v_asset.tenant_id, array['owner', 'operator']::public.user_role[]) then
    raise exception '자산이 없거나 중요도를 변경할 권한이 없습니다' using errcode = 'insufficient_privilege';
  end if;
  if coalesce(p_confidentiality, 0) not between 1 and 3
     or coalesce(p_integrity, 0) not between 1 and 3
     or coalesce(p_availability, 0) not between 1 and 3 then
    raise exception '기밀성·무결성·가용성은 1~3점이어야 합니다' using errcode = 'invalid_parameter_value';
  end if;

  update public.assets
  set confidentiality_score = p_confidentiality, integrity_score = p_integrity, availability_score = p_availability
  where id = p_asset_id;
  v_count := private.recalculate_risk_scores(v_asset.tenant_id, p_asset_id);

  return jsonb_build_object(
    'asset_id', p_asset_id,
    'confidentiality_score', p_confidentiality,
    'integrity_score', p_integrity,
    'availability_score', p_availability,
    'recalculated_items', v_count
  );
end;
$$;

revoke execute on function public.update_asset_importance(uuid, int, int, int) from public, anon, authenticated, service_role;
grant execute on function public.update_asset_importance(uuid, int, int, int) to authenticated;

-- ---------------------------------------------------------------------------
-- 위험도 정책 저장 (owner). 테넌트 전체 점수 재계산.
-- ---------------------------------------------------------------------------
create function public.save_risk_policy(
  p_tenant_id uuid,
  p_confidentiality_weight numeric,
  p_integrity_weight numeric,
  p_availability_weight numeric,
  p_critical_threshold int,
  p_warning_threshold int
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_count int;
begin
  if (select auth.uid()) is null
     or not private.has_tenant_role(p_tenant_id, array['owner']::public.user_role[]) then
    raise exception '위험도 정책을 변경할 권한이 없습니다' using errcode = 'insufficient_privilege';
  end if;
  if coalesce(p_confidentiality_weight, 0) not between 0.50 and 3.00
     or coalesce(p_integrity_weight, 0) not between 0.50 and 3.00
     or coalesce(p_availability_weight, 0) not between 0.50 and 3.00 then
    raise exception '가중치는 0.50~3.00 이어야 합니다' using errcode = 'invalid_parameter_value';
  end if;
  if p_warning_threshold is null or p_critical_threshold is null
     or p_warning_threshold < 1 or p_critical_threshold <= p_warning_threshold or p_critical_threshold > 81 then
    raise exception '등급 기준은 1 ≤ 경고 < 긴급 ≤ 81 이어야 합니다' using errcode = 'invalid_parameter_value';
  end if;

  insert into public.risk_scoring_policies (
    tenant_id, confidentiality_weight, integrity_weight, availability_weight, critical_threshold, warning_threshold
  ) values (
    p_tenant_id, round(p_confidentiality_weight, 2), round(p_integrity_weight, 2), round(p_availability_weight, 2),
    p_critical_threshold, p_warning_threshold
  )
  on conflict (tenant_id) do update
  set confidentiality_weight = excluded.confidentiality_weight,
      integrity_weight = excluded.integrity_weight,
      availability_weight = excluded.availability_weight,
      critical_threshold = excluded.critical_threshold,
      warning_threshold = excluded.warning_threshold;

  v_count := private.recalculate_risk_scores(p_tenant_id, null);
  return jsonb_build_object('tenant_id', p_tenant_id, 'recalculated_items', v_count);
end;
$$;

revoke execute on function public.save_risk_policy(uuid, numeric, numeric, numeric, int, int) from public, anon, authenticated, service_role;
grant execute on function public.save_risk_policy(uuid, numeric, numeric, numeric, int, int) to authenticated;

-- ---------------------------------------------------------------------------
-- 자산 개요 (호출자 권한, RLS 적용): 자산마다 가장 최근 완료 진단의 결과 요약
-- ---------------------------------------------------------------------------
create function public.get_asset_overview(p_tenant_id uuid)
returns table (
  asset_id uuid,
  hostname varchar,
  os_type public.os_family,
  os_version varchar,
  confidentiality_score int,
  integrity_score int,
  availability_score int,
  last_assessed_at timestamptz,
  latest_run_id uuid,
  latest_run_title varchar,
  checks int,
  vulnerable int,
  critical int,
  max_risk_score numeric
)
language sql
stable
security invoker
set search_path = ''
as $$
  with policy as (
    select coalesce((select p.critical_threshold from public.risk_scoring_policies p where p.tenant_id = p_tenant_id), 15) as critical
  )
  select
    a.id, a.hostname, a.os_type, a.os_version,
    a.confidentiality_score, a.integrity_score, a.availability_score, a.last_assessed_at,
    latest.id, latest.title,
    coalesce(stats.checks, 0), coalesce(stats.vulnerable, 0), coalesce(stats.critical, 0),
    coalesce(stats.max_score, 0)
  from public.assets a
  cross join policy
  left join lateral (
    select r.id, r.title
    from public.assessment_runs r
    where r.tenant_id = a.tenant_id and r.status = 'completed'
      and exists (select 1 from public.inspection_item_results i where i.assessment_run_id = r.id and i.asset_id = a.id)
    order by r.created_at desc
    limit 1
  ) latest on true
  left join lateral (
    select
      count(*)::int as checks,
      count(*) filter (where i.final_status = 'vulnerable')::int as vulnerable,
      count(*) filter (where i.final_status = 'vulnerable' and i.calculated_risk_score >= policy.critical)::int as critical,
      max(i.calculated_risk_score) as max_score
    from public.inspection_item_results i
    where i.assessment_run_id = latest.id and i.asset_id = a.id
  ) stats on true
  where a.tenant_id = p_tenant_id
  order by coalesce(stats.max_score, 0) desc, a.hostname;
$$;

revoke execute on function public.get_asset_overview(uuid) from public, anon, authenticated, service_role;
grant execute on function public.get_asset_overview(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- 대시보드 (호출자 권한, RLS 적용)
--   latest: 가장 최근 완료 진단의 요약, trend: 최근 완료 진단 8개의 판정 추이,
--   top_assets: 최근 진단의 위험 점수 합계 상위 5개 자산, categories: 최근 진단의 분야별 분포
-- ---------------------------------------------------------------------------
create function public.get_dashboard_summary(p_tenant_id uuid)
returns jsonb
language sql
stable
security invoker
set search_path = ''
as $$
  with policy as (
    select
      coalesce((select p.critical_threshold from public.risk_scoring_policies p where p.tenant_id = p_tenant_id), 15) as critical,
      coalesce((select p.warning_threshold from public.risk_scoring_policies p where p.tenant_id = p_tenant_id), 8) as warning
  ),
  completed as (
    select r.id, r.title, r.created_at, r.completed_at, r.total_assets
    from public.assessment_runs r
    where r.tenant_id = p_tenant_id and r.status = 'completed'
  ),
  latest as (select * from completed order by created_at desc limit 1),
  latest_items as (
    select i.*, g.category
    from public.inspection_item_results i
    join latest l on l.id = i.assessment_run_id
    join public.compliance_guidelines g on g.item_code = i.item_code
  )
  select jsonb_build_object(
    'asset_count', (select count(*) from public.assets a where a.tenant_id = p_tenant_id),
    'run_count', (select count(*) from public.assessment_runs r where r.tenant_id = p_tenant_id),
    'in_progress_count', (
      select count(*) from public.assessment_runs r
      where r.tenant_id = p_tenant_id and r.status in ('queued', 'parsing', 'scoring')
    ),
    'critical_threshold', (select critical from policy),
    'warning_threshold', (select warning from policy),
    'latest', (
      select jsonb_build_object(
        'id', l.id, 'title', l.title, 'created_at', l.created_at, 'total_assets', l.total_assets,
        'checks', (select count(*) from latest_items),
        'good', (select count(*) from latest_items where final_status = 'good'),
        'vulnerable', (select count(*) from latest_items where final_status = 'vulnerable'),
        'na', (select count(*) from latest_items where final_status = 'na'),
        'critical', (select count(*) from latest_items, policy where final_status = 'vulnerable' and calculated_risk_score >= policy.critical),
        'warning', (select count(*) from latest_items, policy where final_status = 'vulnerable' and calculated_risk_score >= policy.warning and calculated_risk_score < policy.critical),
        'caution', (select count(*) from latest_items, policy where final_status = 'vulnerable' and calculated_risk_score < policy.warning)
      )
      from latest l
    ),
    'trend', coalesce((
      select jsonb_agg(t order by t.created_at)
      from (
        select c.id, c.title, c.created_at,
          (select count(*) from public.inspection_item_results i where i.assessment_run_id = c.id and i.final_status = 'good') as good,
          (select count(*) from public.inspection_item_results i where i.assessment_run_id = c.id and i.final_status = 'vulnerable') as vulnerable
        from completed c
        order by c.created_at desc
        limit 8
      ) t
    ), '[]'::jsonb),
    'top_assets', coalesce((
      select jsonb_agg(t order by t.score_sum desc, t.hostname)
      from (
        select a.id as asset_id, a.hostname,
          count(*) filter (where li.final_status = 'vulnerable') as vulnerable,
          count(*) filter (where li.final_status = 'vulnerable' and li.calculated_risk_score >= (select critical from policy)) as critical,
          sum(li.calculated_risk_score) as score_sum
        from latest_items li
        join public.assets a on a.id = li.asset_id
        group by a.id, a.hostname
        having count(*) filter (where li.final_status = 'vulnerable') > 0
        order by sum(li.calculated_risk_score) desc, a.hostname
        limit 5
      ) t
    ), '[]'::jsonb),
    'categories', coalesce((
      select jsonb_agg(t order by t.category)
      from (
        select li.category::text as category,
          count(*) as checks,
          count(*) filter (where li.final_status = 'vulnerable') as vulnerable,
          count(*) filter (where li.final_status = 'good') as good
        from latest_items li
        group by li.category
      ) t
    ), '[]'::jsonb)
  );
$$;

revoke execute on function public.get_dashboard_summary(uuid) from public, anon, authenticated, service_role;
grant execute on function public.get_dashboard_summary(uuid) to authenticated;

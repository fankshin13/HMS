-- 정량적 위험평가와 수동 판정 변경
--
-- 위험 점수 = 자산 중요도 × 취약 등급 가중치
--   자산 중요도 = 기밀성×W_c + 무결성×W_i + 가용성×W_a  (점수 1~3, 가중치 기본 1.00 → 3~9)
--   취약 등급 가중치 = 상 3, 중 2, 하 1
--   판정이 '취약'이 아니면 0
-- 위험 등급: 긴급 ≥ critical_threshold(기본 15), 경고 ≥ warning_threshold(기본 8), 그 외 주의.
-- 같은 공식이 backend/modules/compliance/risk_evaluator.py 에 있으며, 테스트가 두 구현의 일치를 확인한다.

create function private.risk_level_weight(p_level public.compliance_risk_level)
returns int
language sql
immutable
set search_path = ''
as $$
  select case p_level when 'high' then 3 when 'medium' then 2 else 1 end;
$$;

create function private.compute_risk_score(
  p_status public.item_status,
  p_level public.compliance_risk_level,
  p_confidentiality int,
  p_integrity int,
  p_availability int,
  p_weight_c numeric,
  p_weight_i numeric,
  p_weight_a numeric
)
returns numeric
language sql
immutable
set search_path = ''
as $$
  select case
    when p_status <> 'vulnerable' then 0::numeric
    else round(
      (p_confidentiality * p_weight_c + p_integrity * p_weight_i + p_availability * p_weight_a)
        * private.risk_level_weight(p_level),
      2
    )
  end;
$$;

revoke execute on function private.risk_level_weight(public.compliance_risk_level) from public, anon, authenticated;
revoke execute on function private.compute_risk_score(
  public.item_status, public.compliance_risk_level, int, int, int, numeric, numeric, numeric
) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 수동 판정 변경: 진단 차수 확인, 점수 재산정, 감사 기록, 취약 건수 동기화를 한 트랜잭션에서 처리하고 결과를 돌려준다.
-- 이전 버전(반환값 없음, 진단 차수 미확인)을 대체한다.
-- ---------------------------------------------------------------------------
drop function public.apply_item_override(uuid, public.item_status, text);

create function public.apply_item_override(
  p_run_id uuid,
  p_item_result_id uuid,
  p_new_status public.item_status,
  p_reason text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_reason text := btrim(coalesce(p_reason, ''));
  v_result public.inspection_item_results%rowtype;
  v_actor_id uuid;
  v_score numeric;
  v_audit_id uuid;
  v_vulnerable int;
begin
  if (select auth.uid()) is null then
    raise exception '로그인이 필요합니다' using errcode = 'insufficient_privilege';
  end if;
  if p_new_status is null then
    raise exception '변경할 판정 값을 지정해야 합니다' using errcode = 'invalid_parameter_value';
  end if;
  if length(v_reason) < 5 or length(v_reason) > 1000 then
    raise exception '변경 사유는 공백을 제외하고 5자 이상 1000자 이하로 입력해야 합니다'
      using errcode = 'invalid_parameter_value';
  end if;

  -- 같은 항목을 동시에 바꾸려는 요청을 직렬화한다
  select r.* into v_result
  from public.inspection_item_results r
  where r.id = p_item_result_id and r.assessment_run_id = p_run_id
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

  if v_result.final_status <> p_new_status then
    select private.compute_risk_score(
      p_new_status, g.risk_level,
      a.confidentiality_score, a.integrity_score, a.availability_score,
      coalesce(p.confidentiality_weight, 1.00), coalesce(p.integrity_weight, 1.00), coalesce(p.availability_weight, 1.00)
    ) into v_score
    from public.assets a
    join public.compliance_guidelines g on g.item_code = v_result.item_code
    left join public.risk_scoring_policies p on p.tenant_id = v_result.tenant_id
    where a.id = v_result.asset_id;

    update public.inspection_item_results
    set final_status = p_new_status, calculated_risk_score = v_score
    where id = v_result.id;

    insert into public.override_audit_logs (
      inspection_item_result_id, tenant_id, actor_user_id, previous_status, new_status, override_reason
    ) values (
      v_result.id, v_result.tenant_id, v_actor_id, v_result.final_status, p_new_status, v_reason
    ) returning id into v_audit_id;

    update public.assessment_runs r
    set vulnerable_items_count = (
      select count(*) from public.inspection_item_results i
      where i.assessment_run_id = r.id and i.final_status = 'vulnerable'
    )
    where r.id = v_result.assessment_run_id;
  end if;

  select vulnerable_items_count into v_vulnerable from public.assessment_runs where id = v_result.assessment_run_id;

  return (
    select jsonb_build_object(
      'result_id', r.id,
      'assessment_run_id', r.assessment_run_id,
      'asset_id', r.asset_id,
      'item_code', r.item_code,
      'auto_status', r.auto_status,
      'final_status', r.final_status,
      'calculated_risk_score', r.calculated_risk_score,
      'changed', v_audit_id is not null,
      'audit_id', v_audit_id,
      'vulnerable_items_count', v_vulnerable
    )
    from public.inspection_item_results r
    where r.id = v_result.id
  );
end;
$$;

revoke execute on function public.apply_item_override(uuid, uuid, public.item_status, text)
  from public, anon, authenticated, service_role;
grant execute on function public.apply_item_override(uuid, uuid, public.item_status, text) to authenticated;

-- ---------------------------------------------------------------------------
-- 위험 요약 (호출자 권한 → RLS 적용). 다른 테넌트 차수는 0행.
-- ---------------------------------------------------------------------------
create function public.get_assessment_risk_summary(p_run_id uuid)
returns table (
  vulnerable_count int,
  critical_count int,
  warning_count int,
  caution_count int,
  max_risk_score numeric,
  critical_threshold int,
  warning_threshold int
)
language sql
stable
security invoker
set search_path = ''
as $$
  with policy as (
    select
      coalesce((select p.critical_threshold from public.risk_scoring_policies p where p.tenant_id = r.tenant_id), 15) as critical,
      coalesce((select p.warning_threshold from public.risk_scoring_policies p where p.tenant_id = r.tenant_id), 8) as warning,
      r.id
    from public.assessment_runs r
    where r.id = p_run_id
  )
  select
    count(*) filter (where i.final_status = 'vulnerable')::int,
    count(*) filter (where i.final_status = 'vulnerable' and i.calculated_risk_score >= policy.critical)::int,
    count(*) filter (where i.final_status = 'vulnerable' and i.calculated_risk_score >= policy.warning
                     and i.calculated_risk_score < policy.critical)::int,
    count(*) filter (where i.final_status = 'vulnerable' and i.calculated_risk_score < policy.warning)::int,
    coalesce(max(i.calculated_risk_score), 0),
    policy.critical,
    policy.warning
  from policy
  left join public.inspection_item_results i on i.assessment_run_id = policy.id
  group by policy.critical, policy.warning;
$$;

revoke execute on function public.get_assessment_risk_summary(uuid) from public, anon, authenticated, service_role;
grant execute on function public.get_assessment_risk_summary(uuid) to authenticated;

create index inspection_results_run_score_idx on public.inspection_item_results (assessment_run_id, calculated_risk_score desc);

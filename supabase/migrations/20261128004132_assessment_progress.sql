-- 진단 차수 진행률·요약 집계. 호출자 권한(security invoker)으로 실행되어 RLS 가 그대로 적용된다.
-- 다른 테넌트의 차수를 넣으면 행이 없어 0행을 돌려준다(존재 여부를 드러내지 않음).

create function public.get_assessment_progress(p_run_id uuid)
returns table (
  status public.assessment_status,
  total_assets int,
  processed_assets int,
  quarantined_logs int,
  total_checks int,
  good_count int,
  vulnerable_count int,
  na_count int
)
language sql
stable
security invoker
set search_path = ''
as $$
  select
    r.status,
    r.total_assets,
    (select count(distinct i.asset_id)::int from public.inspection_item_results i where i.assessment_run_id = r.id),
    (select count(*)::int from public.diagnostic_logs l where l.assessment_run_id = r.id and l.parse_status <> 'success'),
    (select count(*)::int from public.inspection_item_results i where i.assessment_run_id = r.id),
    (select count(*)::int from public.inspection_item_results i where i.assessment_run_id = r.id and i.final_status = 'good'),
    (select count(*)::int from public.inspection_item_results i where i.assessment_run_id = r.id and i.final_status = 'vulnerable'),
    (select count(*)::int from public.inspection_item_results i where i.assessment_run_id = r.id and i.final_status = 'na')
  from public.assessment_runs r
  where r.id = p_run_id;
$$;

revoke execute on function public.get_assessment_progress(uuid) from public, anon, authenticated, service_role;
grant execute on function public.get_assessment_progress(uuid) to authenticated;

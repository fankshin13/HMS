-- 복합 외래키(id, tenant_id)를 덮는 인덱스 (Supabase 성능 점검: unindexed_foreign_keys)
-- 부모 행 삭제·갱신 시 자식 테이블 전체 검색을 막고, 진단 차수 단위 조회를 빠르게 한다.
create index if not exists generated_reports_run_tenant_idx on public.generated_reports (assessment_run_id, tenant_id);
create index if not exists inspection_results_asset_tenant_idx on public.inspection_item_results (asset_id, tenant_id);
create index if not exists inspection_results_run_tenant_idx on public.inspection_item_results (assessment_run_id, tenant_id);
create index if not exists override_audit_result_tenant_idx on public.override_audit_logs (inspection_item_result_id, tenant_id);
create index if not exists purge_audit_run_tenant_idx on public.purge_audit_logs (assessment_run_id, tenant_id);
create index if not exists report_jobs_requester_tenant_idx on public.report_jobs (requested_by, tenant_id);
create index if not exists report_jobs_run_tenant_idx on public.report_jobs (assessment_run_id, tenant_id);

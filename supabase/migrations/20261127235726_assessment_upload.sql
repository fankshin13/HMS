-- 진단 파일 업로드: 원본 로그 비공개 저장소 + 진단 차수·자산·로그 메타데이터 원자적 등록
--
-- 저장 경로 규칙: diagnostic-raw/<tenant_id>/<assessment_run_id>/<파일명>
-- 업로드·조회·삭제는 해당 테넌트의 활성 owner/operator 만 가능하다(viewer 는 원본 로그에 접근하지 않음).
-- 저장 데이터는 Supabase Storage 기본 저장 시 암호화(AES-256)가 적용된다.

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('diagnostic-raw', 'diagnostic-raw', false, 52428800, array['text/plain'])
on conflict (id) do nothing;

-- 경로의 첫 폴더(테넌트 ID)를 안전하게 uuid 로 바꾼다. 형식이 틀리면 null(→ 정책 거부).
create function private.try_uuid(p_value text)
returns uuid
language plpgsql
immutable
set search_path = ''
as $$
begin
  return p_value::uuid;
exception
  when invalid_text_representation then
    return null;
end;
$$;

revoke execute on function private.try_uuid(text) from public, anon, authenticated;
grant execute on function private.try_uuid(text) to authenticated;

create policy diagnostic_raw_insert_operator on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'diagnostic-raw'
    and (select private.has_tenant_role(
      private.try_uuid((storage.foldername(name))[1]),
      array['owner', 'operator']::public.user_role[]
    ))
  );

create policy diagnostic_raw_select_operator on storage.objects
  for select to authenticated
  using (
    bucket_id = 'diagnostic-raw'
    and (select private.has_tenant_role(
      private.try_uuid((storage.foldername(name))[1]),
      array['owner', 'operator']::public.user_role[]
    ))
  );

create policy diagnostic_raw_delete_operator on storage.objects
  for delete to authenticated
  using (
    bucket_id = 'diagnostic-raw'
    and (select private.has_tenant_role(
      private.try_uuid((storage.foldername(name))[1]),
      array['owner', 'operator']::public.user_role[]
    ))
  );

-- ---------------------------------------------------------------------------
-- 업로드 등록 (owner/operator)
-- p_logs: [{ file_name, file_size_bytes, storage_path, parse_status, hostname?, os_type?, os_version?,
--            detected_ip?, quarantined_error_lines, error_details? }, ...]
-- 같은 테넌트에서 10분 안에 같은 SHA-256 파일이 등록된 적이 있으면 p_allow_duplicate 없이는 거부한다.
-- ---------------------------------------------------------------------------
create function public.register_assessment_upload(
  p_run_id uuid,
  p_tenant_id uuid,
  p_title text,
  p_sha256 text,
  p_logs jsonb,
  p_allow_duplicate boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_title text := btrim(coalesce(p_title, ''));
  v_prefix text := p_tenant_id::text || '/' || p_run_id::text || '/';
  v_log jsonb;
  v_asset_id uuid;
  v_preview jsonb := '[]'::jsonb;
  v_duplicate uuid;
  v_quarantined int := 0;
begin
  if not private.has_tenant_role(p_tenant_id, array['owner', 'operator']::public.user_role[]) then
    raise exception '진단 파일을 업로드할 권한이 없습니다' using errcode = 'insufficient_privilege';
  end if;
  if length(v_title) = 0 or length(v_title) > 200 then
    raise exception '진단명은 1~200자여야 합니다' using errcode = 'invalid_parameter_value';
  end if;
  if p_sha256 is null or p_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception '파일 체크섬 형식이 올바르지 않습니다' using errcode = 'invalid_parameter_value';
  end if;
  if jsonb_typeof(p_logs) <> 'array' or jsonb_array_length(p_logs) = 0 or jsonb_array_length(p_logs) > 500 then
    raise exception '등록할 로그 파일은 1~500개여야 합니다' using errcode = 'invalid_parameter_value';
  end if;

  select r.id into v_duplicate
  from public.assessment_runs r
  where r.tenant_id = p_tenant_id
    and r.raw_archive_sha256 = p_sha256
    and r.created_at > now() - interval '10 minutes'
  limit 1;
  if v_duplicate is not null and not coalesce(p_allow_duplicate, false) then
    raise exception '같은 파일이 10분 안에 이미 업로드되었습니다'
      using errcode = 'unique_violation', detail = v_duplicate::text;
  end if;

  insert into public.assessment_runs (id, tenant_id, title, status, raw_archive_sha256)
  values (p_run_id, p_tenant_id, v_title, 'queued', p_sha256);

  for v_log in select value from jsonb_array_elements(p_logs) loop
    -- 저장 경로는 반드시 이 테넌트·이 진단 차수 폴더 아래여야 한다
    if not starts_with(coalesce(v_log ->> 'storage_path', ''), v_prefix)
       or position('..' in v_log ->> 'storage_path') > 0 then
      raise exception '저장 경로가 올바르지 않습니다' using errcode = 'invalid_parameter_value';
    end if;

    v_asset_id := null;
    if nullif(v_log ->> 'hostname', '') is not null then
      insert into public.assets (tenant_id, hostname, os_type, os_version)
      values (
        p_tenant_id,
        v_log ->> 'hostname',
        (v_log ->> 'os_type')::public.os_family,
        nullif(left(v_log ->> 'os_version', 100), '')
      )
      on conflict (tenant_id, hostname) do update
        set os_type = excluded.os_type,
            os_version = coalesce(excluded.os_version, public.assets.os_version)
      returning id into v_asset_id;
    end if;

    if (v_log ->> 'parse_status') <> 'success' then
      v_quarantined := v_quarantined + 1;
    end if;

    insert into public.diagnostic_logs (
      tenant_id, assessment_run_id, asset_id, file_name, file_size_bytes, storage_path,
      parse_status, quarantined_error_lines, error_details
    ) values (
      p_tenant_id,
      p_run_id,
      v_asset_id,
      left(v_log ->> 'file_name', 255),
      (v_log ->> 'file_size_bytes')::bigint,
      v_log ->> 'storage_path',
      (v_log ->> 'parse_status')::public.parsing_status,
      coalesce((v_log ->> 'quarantined_error_lines')::int, 0),
      v_log -> 'error_details'
    );

    v_preview := v_preview || jsonb_build_object(
      'asset_id', v_asset_id,
      'hostname', v_log ->> 'hostname',
      'os_type', v_log ->> 'os_type',
      'detected_ip', v_log ->> 'detected_ip',
      'file_name', v_log ->> 'file_name',
      'parse_status', v_log ->> 'parse_status',
      'error_details', v_log -> 'error_details'
    );
  end loop;

  update public.assessment_runs
  set total_assets = (
    select count(distinct l.asset_id) from public.diagnostic_logs l
    where l.assessment_run_id = p_run_id and l.asset_id is not null
  )
  where id = p_run_id;

  return jsonb_build_object(
    'assessment_run_id', p_run_id,
    'title', v_title,
    'status', 'queued',
    'total_assets', (select total_assets from public.assessment_runs where id = p_run_id),
    'quarantined_files', v_quarantined,
    'assets_preview', v_preview
  );
end;
$$;

revoke execute on function public.register_assessment_upload(uuid, uuid, text, text, jsonb, boolean)
  from public, anon, authenticated, service_role;
grant execute on function public.register_assessment_upload(uuid, uuid, text, text, jsonb, boolean)
  to authenticated;

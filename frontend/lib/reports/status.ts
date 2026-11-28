import "server-only";

import type { createClient } from "@/lib/supabase/server";
import { REPORT_TITLES, REPORT_TYPES, type ReportStatus } from "./reports";

type Supabase = Awaited<ReturnType<typeof createClient>>;

/**
 * 보고서 조판 상태와 내려받을 수 있는 산출물. RLS 로 같은 테넌트만 조회된다.
 * 진단 차수가 보이지 않으면 null(다른 테넌트·없음).
 * 조판이 끝났어도 보존 기한(24시간)이 지난 파일은 목록에서 빠지고, 6개가 모두 있어야 '완료'로 본다.
 */
export async function loadReportStatus(
  supabase: Supabase,
  runId: string,
): Promise<ReportStatus | null> {
  const nowIso = new Date().toISOString();
  const [run, job, files] = await Promise.all([
    supabase
      .from("assessment_runs")
      .select("id, raw_logs_purged_at, tenants(zero_retention_enabled)")
      .eq("id", runId)
      .maybeSingle(),
    supabase
      .from("report_jobs")
      .select("status, progress_percentage, current_step, error_message")
      .eq("assessment_run_id", runId)
      .maybeSingle(),
    supabase
      .from("generated_reports")
      .select("id, report_type, format, file_size_bytes, expires_at")
      .eq("assessment_run_id", runId)
      .gt("expires_at", nowIso),
  ]);
  const failure = run.error ?? job.error ?? files.error;
  if (failure) {
    console.error("보고서 상태 조회 실패", failure.code);
    throw new Error("보고서 상태를 불러오지 못했습니다");
  }
  if (!run.data) return null;

  const base = `/api/assessments/${runId}/reports`;
  const valid = files.data ?? [];
  const complete = job.data?.status === "completed" && valid.length === 6;
  const status: ReportStatus["status"] = !job.data
    ? "none"
    : job.data.status === "completed" && !complete
      ? "none" // 보존 기한이 지나 파일이 정리됨
      : job.data.status;

  return {
    assessment_run_id: runId,
    status,
    progress_percentage:
      status === "none" ? 0 : (job.data?.progress_percentage ?? 0),
    current_step:
      status === "none" ? "none" : (job.data?.current_step ?? "none"),
    error_message:
      status === "failed" ? (job.data?.error_message ?? null) : null,
    zero_retention_active: run.data.tenants?.zero_retention_enabled ?? true,
    raw_logs_purged: run.data.raw_logs_purged_at !== null,
    raw_logs_purged_at: run.data.raw_logs_purged_at,
    expires_at: complete
      ? (valid.map((f) => f.expires_at).sort()[0] ?? null)
      : null,
    reports: REPORT_TYPES.map((type) => {
      const pick = (format: "docx" | "pdf") => {
        const file = complete
          ? valid.find((f) => f.report_type === type && f.format === format)
          : undefined;
        return file
          ? {
              report_id: file.id,
              file_size_bytes: file.file_size_bytes,
              download_url: `${base}/${type}/download?format=${format}`,
            }
          : null;
      };
      return {
        report_type: type,
        title: REPORT_TITLES[type],
        docx: pick("docx"),
        pdf: pick("pdf"),
      };
    }),
    bundle_download_url: complete ? `${base}/bundle/download` : null,
  };
}

import "server-only";

import { apiError } from "@/lib/assessments/api";
import type { createClient } from "@/lib/supabase/server";
import type { ReportFormat, ReportType } from "./reports";

type Supabase = Awaited<ReturnType<typeof createClient>>;

export type ReportFile = {
  type: ReportType;
  format: ReportFormat;
  bytes: Uint8Array;
};

/**
 * 보고서 파일을 사용자 세션으로 내려받는다. 저장소 정책(테넌트 구성원만 읽기)과 generated_reports RLS 가
 * 함께 적용되므로 다른 테넌트의 파일은 찾을 수 없다. 보존 기한이 지난 파일은 410.
 */
export async function fetchReportFiles(
  supabase: Supabase,
  runId: string,
  wanted: { type: ReportType; format: ReportFormat }[],
): Promise<{ files: ReportFile[]; runTitle: string } | Response> {
  const [run, rows] = await Promise.all([
    supabase
      .from("assessment_runs")
      .select("title")
      .eq("id", runId)
      .maybeSingle(),
    supabase
      .from("generated_reports")
      .select("report_type, format, storage_path, expires_at")
      .eq("assessment_run_id", runId),
  ]);
  if (run.error || rows.error) {
    console.error("보고서 조회 실패", run.error?.code ?? rows.error?.code);
    return apiError(500, "download_failed", "보고서를 불러오지 못했습니다.");
  }
  if (!run.data)
    return apiError(404, "not_found", "보고서를 찾을 수 없습니다.");

  const now = Date.now();
  const files: ReportFile[] = [];
  for (const { type, format } of wanted) {
    const row = rows.data.find(
      (r) => r.report_type === type && r.format === format,
    );
    if (!row)
      return apiError(
        404,
        "not_found",
        "보고서를 찾을 수 없습니다. 먼저 보고서를 생성해 주세요.",
      );
    if (new Date(row.expires_at).getTime() <= now)
      return apiError(
        410,
        "expired",
        "보존 기한(24시간)이 지나 삭제된 보고서입니다. 다시 생성해 주세요.",
      );
    const { data, error } = await supabase.storage
      .from("reports")
      .download(row.storage_path);
    if (error || !data) {
      console.error("보고서 파일 다운로드 실패");
      return apiError(
        404,
        "not_found",
        "보고서 파일을 찾을 수 없습니다. 다시 생성해 주세요.",
      );
    }
    files.push({
      type,
      format,
      bytes: new Uint8Array(await data.arrayBuffer()),
    });
  }
  return { files, runTitle: run.data.title };
}

/** Asia/Seoul 기준 YYYYMMDD */
export function seoulCompactDate(now = new Date()): string {
  return new Intl.DateTimeFormat("sv-SE", { timeZone: "Asia/Seoul" })
    .format(now)
    .replaceAll("-", "");
}

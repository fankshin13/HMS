import { type NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { apiError } from "@/lib/assessments/api";
import { createClient, getAuthUserId } from "@/lib/supabase/server";
import { getMembership } from "@/lib/workspace";

const NOT_FOUND = "진단 차수를 찾을 수 없습니다.";
const bodySchema = z.object({ confirm_purge: z.literal(true) });
const resultSchema = z.object({
  purged_log_count: z.number(),
  purged_at: z.string(),
});

/**
 * 원본 진단 로그 영구 파기 (owner·operator). 저장소 객체를 먼저 지운 뒤 DB 참조를 정리하고 감사 기록을 남긴다.
 * 반복 호출해도 안전하다. 보고서(24시간 보존)는 남겨 재다운로드할 수 있다.
 */
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const id = z
    .string()
    .uuid()
    .safeParse((await params).id);
  if (!id.success) return apiError(404, "not_found", NOT_FOUND);
  const supabase = await createClient();
  const userId = await getAuthUserId(supabase);
  if (!userId) return apiError(401, "unauthorized", "로그인이 필요합니다.");
  const membership = await getMembership(supabase, userId);
  if (!membership || membership.role === "viewer")
    return apiError(
      403,
      "forbidden",
      "원본 파기는 워크스페이스 소유자 또는 작업자만 할 수 있습니다.",
    );

  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return apiError(400, "bad_request", "요청 본문을 읽을 수 없습니다.");
  }
  if (!bodySchema.safeParse(raw).success)
    return apiError(
      422,
      "confirmation_required",
      "confirm_purge 가 true 여야 합니다.",
    );

  const { data: logs, error: logsError } = await supabase
    .from("diagnostic_logs")
    .select("storage_path")
    .eq("assessment_run_id", id.data)
    .not("storage_path", "is", null);
  if (logsError) {
    console.error("원본 로그 조회 실패", logsError.code);
    return apiError(500, "purge_failed", "원본 로그를 파기하지 못했습니다.");
  }
  const paths = logs.flatMap((l) => (l.storage_path ? [l.storage_path] : []));
  for (let start = 0; start < paths.length; start += 100) {
    const { error } = await supabase.storage
      .from("diagnostic-raw")
      .remove(paths.slice(start, start + 100));
    if (error) {
      console.error("원본 로그 저장소 삭제 실패");
      return apiError(
        502,
        "purge_failed",
        "저장소에서 원본 로그를 삭제하지 못했습니다. 다시 시도해 주세요.",
      );
    }
  }

  const { data, error } = await supabase.rpc("purge_raw_diagnostic_data", {
    p_run_id: id.data,
    p_purge_reports: false,
  });
  if (error) {
    if (error.code === "42501") return apiError(404, "not_found", NOT_FOUND);
    console.error("원본 파기 기록 실패", error.code);
    return apiError(500, "purge_failed", "원본 로그를 파기하지 못했습니다.");
  }
  const result = resultSchema.safeParse(data);
  if (!result.success)
    return apiError(500, "purge_failed", "원본 로그를 파기하지 못했습니다.");
  return NextResponse.json({
    message: "Raw diagnostic logs successfully purged",
    purged_log_count: result.data.purged_log_count,
    purged_at: result.data.purged_at,
  });
}

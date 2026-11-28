import { type NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { apiError } from "@/lib/assessments/api";
import { createClient, getAuthUserId } from "@/lib/supabase/server";
import { getMembership } from "@/lib/workspace";

const NOT_FOUND = "진단 차수를 찾을 수 없습니다.";
const resultSchema = z.object({
  assessment_run_id: z.string(),
  status: z.enum(["queued", "rendering", "completed"]),
  dispatched: z.boolean(),
});

/**
 * 3종 보고서 일괄 조판 요청 (owner·operator). 멱등: 진행 중이면 그 상태, 유효한 산출물이 있으면
 * 완료 상태를 돌려준다. ?force=true 이면 다시 조판한다. 실제 조판은 백엔드 워커가 수행한다.
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
  if (!membership || membership.role === "viewer") {
    return apiError(
      403,
      "forbidden",
      "보고서 생성은 워크스페이스 소유자 또는 작업자만 할 수 있습니다.",
    );
  }

  const force = request.nextUrl.searchParams.get("force") === "true";
  const { data, error } = await supabase.rpc("request_report_generation", {
    p_run_id: id.data,
    p_force: force,
  });
  if (error) {
    if (error.code === "42501") return apiError(404, "not_found", NOT_FOUND);
    if (error.code === "55000")
      return apiError(
        409,
        "analysis_incomplete",
        "진단 분석이 완료되지 않아 보고서를 생성할 수 없습니다.",
      );
    console.error("보고서 조판 요청 실패", error.code);
    return apiError(
      500,
      "generate_failed",
      "보고서 생성을 요청하지 못했습니다. 잠시 후 다시 시도해 주세요.",
    );
  }
  const result = resultSchema.safeParse(data);
  if (!result.success) {
    console.error("보고서 조판 요청 응답 형식 오류");
    return apiError(
      500,
      "generate_failed",
      "보고서 생성을 요청하지 못했습니다.",
    );
  }
  return NextResponse.json(
    {
      message: result.data.dispatched
        ? "Report generation pipeline dispatched"
        : "Report generation already in progress or completed",
      ...result.data,
    },
    { status: result.data.status === "completed" ? 200 : 202 },
  );
}

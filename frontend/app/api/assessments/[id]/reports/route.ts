import { type NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { apiError } from "@/lib/assessments/api";
import { loadReportStatus } from "@/lib/reports/status";
import { createClient, getAuthUserId } from "@/lib/supabase/server";

const NOT_FOUND = "진단 차수를 찾을 수 없습니다.";

/** 보고서 조판 상태와 산출물 목록 (owner·operator·viewer) */
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const id = z
    .string()
    .uuid()
    .safeParse((await params).id);
  if (!id.success) return apiError(404, "not_found", NOT_FOUND);
  const supabase = await createClient();
  if (!(await getAuthUserId(supabase)))
    return apiError(401, "unauthorized", "로그인이 필요합니다.");
  try {
    const status = await loadReportStatus(supabase, id.data);
    if (!status) return apiError(404, "not_found", NOT_FOUND);
    return NextResponse.json(status, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return apiError(
      500,
      "status_failed",
      "보고서 상태를 불러오지 못했습니다. 잠시 후 다시 시도해 주세요.",
    );
  }
}

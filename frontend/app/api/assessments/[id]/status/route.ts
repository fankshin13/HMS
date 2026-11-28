import { type NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { progressPercentage } from "@/lib/assessments/labels";
import { createClient, getAuthUserId } from "@/lib/supabase/server";

/** 진단 진행률 폴링. RLS 로 자기 테넌트 차수만 보이며, 다른 테넌트 차수는 404 이다. */
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const id = z
    .string()
    .uuid()
    .safeParse((await params).id);
  if (!id.success) {
    return NextResponse.json(
      {
        error: { code: "not_found", message: "진단 차수를 찾을 수 없습니다." },
      },
      { status: 404 },
    );
  }

  const supabase = await createClient();
  if (!(await getAuthUserId(supabase))) {
    return NextResponse.json(
      { error: { code: "unauthorized", message: "로그인이 필요합니다." } },
      { status: 401 },
    );
  }

  const { data, error } = await supabase
    .rpc("get_assessment_progress", { p_run_id: id.data })
    .maybeSingle();
  if (error) {
    console.error("진단 진행률 조회 실패", error.code);
    return NextResponse.json(
      {
        error: {
          code: "status_failed",
          message:
            "진단 상태를 불러오지 못했습니다. 잠시 후 다시 시도해 주세요.",
        },
      },
      { status: 500 },
    );
  }
  if (!data) {
    return NextResponse.json(
      {
        error: { code: "not_found", message: "진단 차수를 찾을 수 없습니다." },
      },
      { status: 404 },
    );
  }

  return NextResponse.json(
    {
      assessment_run_id: id.data,
      status: data.status,
      progress_percentage: progressPercentage(
        data.status,
        data.total_assets,
        data.processed_assets,
      ),
      total_assets: data.total_assets,
      processed_assets: data.processed_assets,
      quarantined_assets: data.quarantined_logs,
      vulnerable_items_count: data.vulnerable_count,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}

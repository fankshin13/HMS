import { type NextRequest, NextResponse } from "next/server";
import { NOT_FOUND, apiError, routeIdsSchema } from "@/lib/assessments/api";
import { createClient, getAuthUserId } from "@/lib/supabase/server";

/** 점검 항목의 판정 변경 이력(최신순). RLS 로 같은 테넌트 멤버만 조회된다. */
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string; itemId: string }> },
) {
  const ids = routeIdsSchema.safeParse(await params);
  if (!ids.success) return apiError(404, "not_found", NOT_FOUND);

  const supabase = await createClient();
  if (!(await getAuthUserId(supabase)))
    return apiError(401, "unauthorized", "로그인이 필요합니다.");

  const [item, audits] = await Promise.all([
    supabase
      .from("inspection_item_results")
      .select("id, item_code")
      .eq("id", ids.data.itemId)
      .eq("assessment_run_id", ids.data.id)
      .maybeSingle(),
    supabase
      .from("override_audit_logs")
      .select(
        "id, actor_user_id, previous_status, new_status, override_reason, created_at, users(name, email)",
      )
      .eq("inspection_item_result_id", ids.data.itemId)
      .order("created_at", { ascending: false }),
  ]);
  if (item.error || audits.error) {
    console.error(
      "변경 이력 조회 실패",
      item.error?.code ?? audits.error?.code,
    );
    return apiError(
      500,
      "audits_failed",
      "변경 이력을 불러오지 못했습니다. 잠시 후 다시 시도해 주세요.",
    );
  }
  if (!item.data) return apiError(404, "not_found", NOT_FOUND);

  return NextResponse.json({
    item_result_id: item.data.id,
    item_code: item.data.item_code,
    audits: audits.data.map((a) => ({
      audit_id: a.id,
      actor_id: a.actor_user_id,
      actor_name: a.users?.name ?? null,
      actor_email: a.users?.email ?? null,
      previous_status: a.previous_status,
      new_status: a.new_status,
      reason: a.override_reason,
      created_at: a.created_at,
    })),
  });
}

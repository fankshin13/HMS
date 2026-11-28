import { type NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { NOT_FOUND, apiError, routeIdsSchema } from "@/lib/assessments/api";
import { riskCategory } from "@/lib/assessments/risk";
import { createClient, getAuthUserId } from "@/lib/supabase/server";
import { getMembership } from "@/lib/workspace";

const bodySchema = z.object({
  new_status: z.enum(["good", "vulnerable", "na"], {
    message: "변경할 판정을 선택해 주세요.",
  }),
  reason: z
    .string({ message: "변경 사유를 입력해 주세요." })
    .trim()
    .min(5, "변경 사유는 공백을 제외하고 5자 이상 입력해야 합니다.")
    .max(1000, "변경 사유는 1000자 이하로 입력해 주세요."),
});

const rpcResultSchema = z.object({
  result_id: z.string(),
  assessment_run_id: z.string(),
  asset_id: z.string(),
  item_code: z.string(),
  auto_status: z.enum(["good", "vulnerable", "na"]),
  final_status: z.enum(["good", "vulnerable", "na"]),
  calculated_risk_score: z.coerce.number(),
  changed: z.boolean(),
  audit_id: z.string().nullable(),
  vulnerable_items_count: z.number(),
});

/** 점검 항목 판정 수동 변경: owner·operator 만, 사유 5자 이상, 점수 재산정·감사 기록·취약 건수 동기화는 DB 함수가 한 번에 처리 */
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string; itemId: string }> },
) {
  const ids = routeIdsSchema.safeParse(await params);
  if (!ids.success) return apiError(404, "not_found", NOT_FOUND);

  const supabase = await createClient();
  const userId = await getAuthUserId(supabase);
  if (!userId) return apiError(401, "unauthorized", "로그인이 필요합니다.");
  const membership = await getMembership(supabase, userId);
  if (!membership || membership.role === "viewer") {
    return apiError(
      403,
      "forbidden",
      "판정 변경은 워크스페이스 소유자 또는 작업자만 할 수 있습니다.",
    );
  }

  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return apiError(400, "bad_request", "요청 본문을 읽을 수 없습니다.");
  }
  const body = bodySchema.safeParse(raw);
  if (!body.success) {
    return apiError(
      422,
      "invalid_input",
      body.error.issues[0]?.message ?? "입력값을 확인해 주세요.",
    );
  }

  const { data, error } = await supabase.rpc("apply_item_override", {
    p_run_id: ids.data.id,
    p_item_result_id: ids.data.itemId,
    p_new_status: body.data.new_status,
    p_reason: body.data.reason,
  });
  if (error) {
    if (error.code === "42501") return apiError(404, "not_found", NOT_FOUND);
    if (error.code === "22023")
      return apiError(422, "invalid_input", error.message);
    console.error("판정 변경 실패", error.code);
    return apiError(
      500,
      "override_failed",
      "판정을 변경하지 못했습니다. 잠시 후 다시 시도해 주세요.",
    );
  }
  const result = rpcResultSchema.safeParse(data);
  if (!result.success) {
    console.error("판정 변경 응답 형식 오류");
    return apiError(
      500,
      "override_failed",
      "판정을 변경하지 못했습니다. 잠시 후 다시 시도해 주세요.",
    );
  }

  const [summary, audit, run] = await Promise.all([
    supabase
      .rpc("get_assessment_risk_summary", { p_run_id: ids.data.id })
      .maybeSingle(),
    supabase
      .from("override_audit_logs")
      .select(
        "id, previous_status, new_status, override_reason, created_at, users(name)",
      )
      .eq("inspection_item_result_id", ids.data.itemId)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle(),
    supabase
      .from("assessment_runs")
      .select("total_assets")
      .eq("id", ids.data.id)
      .maybeSingle(),
  ]);
  if (summary.error || audit.error || run.error) {
    console.error(
      "판정 변경 후 조회 실패",
      summary.error?.code ?? audit.error?.code ?? run.error?.code,
    );
  }

  const r = result.data;
  const thresholds = {
    critical: summary.data?.critical_threshold ?? 15,
    warning: summary.data?.warning_threshold ?? 8,
  };
  return NextResponse.json({
    result_id: r.result_id,
    assessment_run_id: r.assessment_run_id,
    asset_id: r.asset_id,
    item_code: r.item_code,
    auto_status: r.auto_status,
    final_status: r.final_status,
    calculated_risk_score: r.calculated_risk_score,
    risk_level_category:
      riskCategory(r.final_status, r.calculated_risk_score, thresholds) ??
      "safe",
    changed: r.changed,
    is_overridden: r.auto_status !== r.final_status || audit.data !== null,
    latest_override: audit.data
      ? {
          audit_id: audit.data.id,
          actor_name: audit.data.users?.name ?? null,
          previous_status: audit.data.previous_status,
          new_status: audit.data.new_status,
          reason: audit.data.override_reason,
          created_at: audit.data.created_at,
        }
      : null,
    assessment_summary: {
      total_assets: run.data?.total_assets ?? null,
      vulnerable_items_count: r.vulnerable_items_count,
    },
  });
}

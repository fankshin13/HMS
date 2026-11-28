"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { createClient, getAuthUserId } from "@/lib/supabase/server";
import { getMembership } from "@/lib/workspace";

export type PolicyState = {
  status: "idle" | "saved" | "error";
  message: string;
};

const weight = z.coerce
  .number()
  .min(0.5, "가중치는 0.5~3.0 사이여야 합니다.")
  .max(3, "가중치는 0.5~3.0 사이여야 합니다.");
const schema = z
  .object({
    confidentialityWeight: weight,
    integrityWeight: weight,
    availabilityWeight: weight,
    criticalThreshold: z.coerce
      .number()
      .int()
      .max(81, "긴급 기준은 81점 이하여야 합니다."),
    warningThreshold: z.coerce
      .number()
      .int()
      .min(1, "경고 기준은 1점 이상이어야 합니다."),
  })
  .refine((v) => v.warningThreshold < v.criticalThreshold, {
    message: "경고 기준은 긴급 기준보다 낮아야 합니다.",
  });

/** 위험도 정책 저장(owner). 테넌트의 모든 위험 점수를 새 정책으로 다시 계산한다. */
export async function saveRiskPolicy(
  _prev: PolicyState,
  formData: FormData,
): Promise<PolicyState> {
  const parsed = schema.safeParse(Object.fromEntries(formData));
  if (!parsed.success)
    return {
      status: "error",
      message: parsed.error.issues[0]?.message ?? "입력값을 확인해 주세요.",
    };

  const supabase = await createClient();
  const userId = await getAuthUserId(supabase);
  const membership = userId ? await getMembership(supabase, userId) : null;
  if (membership?.role !== "owner")
    return {
      status: "error",
      message: "위험도 정책은 워크스페이스 소유자만 바꿀 수 있습니다.",
    };

  const v = parsed.data;
  const { data, error } = await supabase.rpc("save_risk_policy", {
    p_tenant_id: membership.tenantId,
    p_confidentiality_weight: v.confidentialityWeight,
    p_integrity_weight: v.integrityWeight,
    p_availability_weight: v.availabilityWeight,
    p_critical_threshold: v.criticalThreshold,
    p_warning_threshold: v.warningThreshold,
  });
  if (error) {
    console.error("위험도 정책 저장 실패", error.code);
    return {
      status: "error",
      message:
        error.code === "22023"
          ? "입력값이 허용 범위를 벗어났습니다."
          : "정책을 저장하지 못했습니다. 다시 시도해 주세요.",
    };
  }
  const count = z.object({ recalculated_items: z.number() }).safeParse(data);
  revalidatePath("/", "layout");
  return {
    status: "saved",
    message: `저장했습니다. 판정 결과 ${count.success ? count.data.recalculated_items : 0}건의 위험 점수를 다시 계산했습니다.`,
  };
}

"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { createClient, getAuthUserId } from "@/lib/supabase/server";
import { getMembership } from "@/lib/workspace";

export type ImportanceState = {
  status: "idle" | "saved" | "error";
  message: string;
};

const score = z.coerce.number().int().min(1).max(3);
const schema = z.object({
  assetId: z.string().uuid(),
  confidentiality: score,
  integrity: score,
  availability: score,
});

/** 자산 중요도(C·I·A) 변경. DB 함수가 권한을 확인하고 위험 점수를 다시 계산한다. */
export async function updateImportance(
  _prev: ImportanceState,
  formData: FormData,
): Promise<ImportanceState> {
  const parsed = schema.safeParse(Object.fromEntries(formData));
  if (!parsed.success)
    return {
      status: "error",
      message: "기밀성·무결성·가용성은 1~3점이어야 합니다.",
    };

  const supabase = await createClient();
  const userId = await getAuthUserId(supabase);
  const membership = userId ? await getMembership(supabase, userId) : null;
  if (!membership || membership.role === "viewer")
    return {
      status: "error",
      message: "자산 중요도는 소유자 또는 작업자만 바꿀 수 있습니다.",
    };

  const { data, error } = await supabase.rpc("update_asset_importance", {
    p_asset_id: parsed.data.assetId,
    p_confidentiality: parsed.data.confidentiality,
    p_integrity: parsed.data.integrity,
    p_availability: parsed.data.availability,
  });
  if (error) {
    if (error.code === "42501")
      return {
        status: "error",
        message: "자산을 찾을 수 없거나 권한이 없습니다.",
      };
    console.error("자산 중요도 변경 실패", error.code);
    return {
      status: "error",
      message: "중요도를 저장하지 못했습니다. 다시 시도해 주세요.",
    };
  }
  const count = z.object({ recalculated_items: z.number() }).safeParse(data);
  revalidatePath("/assets");
  revalidatePath("/dashboard");
  return {
    status: "saved",
    message: `저장했습니다. 판정 결과 ${count.success ? count.data.recalculated_items : 0}건의 위험 점수를 다시 계산했습니다.`,
  };
}

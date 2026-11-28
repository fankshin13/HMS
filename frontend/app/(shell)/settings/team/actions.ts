"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import {
  generateInvitationToken,
  hashInvitationToken,
} from "@/lib/invitations/token";
import { serverEnv } from "@/lib/server-env";
import { createClient, getAuthUserId } from "@/lib/supabase/server";
import { getMembership } from "@/lib/workspace";

export type InviteFormState =
  | { status: "idle" }
  | { status: "error"; message: string }
  | { status: "created"; inviteUrl: string; expiresAt: string; email: string };

const inviteSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, "이름을 입력해 주세요.")
    .max(100, "이름은 100자 이내로 입력해 주세요."),
  email: z
    .string()
    .trim()
    .toLowerCase()
    .email("이메일 주소 형식을 확인해 주세요.")
    .max(255),
  role: z.enum(["operator", "viewer"], { message: "역할을 선택해 주세요." }),
  validHours: z.coerce
    .number()
    .int()
    .min(1, "유효기간은 1~72시간이어야 합니다.")
    .max(72, "유효기간은 1~72시간이어야 합니다."),
});

const FORBIDDEN = "팀원 초대는 워크스페이스 소유자만 할 수 있습니다.";

async function requireOwner() {
  const supabase = await createClient();
  const userId = await getAuthUserId(supabase);
  if (!userId) return { supabase, owner: null };
  const membership = await getMembership(supabase, userId);
  return { supabase, owner: membership?.role === "owner" ? membership : null };
}

export async function createInvitation(
  _prev: InviteFormState,
  formData: FormData,
): Promise<InviteFormState> {
  const parsed = inviteSchema.safeParse(Object.fromEntries(formData));
  if (!parsed.success) {
    return {
      status: "error",
      message: parsed.error.issues[0]?.message ?? "입력값을 확인해 주세요.",
    };
  }

  const { supabase, owner } = await requireOwner();
  if (!owner) return { status: "error", message: FORBIDDEN };

  const rawToken = generateInvitationToken();
  const { data, error } = await supabase
    .rpc("create_invitation", {
      p_tenant_id: owner.tenantId,
      p_email: parsed.data.email,
      p_name: parsed.data.name,
      p_role: parsed.data.role,
      p_token_hash: hashInvitationToken(
        rawToken,
        serverEnv.invitationTokenSalt(),
      ),
      p_valid_hours: parsed.data.validHours,
    })
    .single();

  if (error) {
    if (error.code === "23505") {
      return {
        status: "error",
        message: "이미 등록된 사용자입니다. 팀원 목록을 확인해 주세요.",
      };
    }
    if (error.code === "42501") return { status: "error", message: FORBIDDEN };
    if (error.code === "22023")
      return { status: "error", message: error.message };
    console.error("초대 생성 실패", error.code);
    return {
      status: "error",
      message: "초대 링크 생성에 실패했습니다. 잠시 후 다시 시도해 주세요.",
    };
  }

  revalidatePath("/settings/team");
  const inviteUrl = `${serverEnv.appUrl()}/auth/verify?${new URLSearchParams({ token: rawToken })}`;
  return {
    status: "created",
    inviteUrl,
    expiresAt: data.expires_at,
    email: parsed.data.email,
  };
}

export type RevokeState = { error: string | null };

export async function revokeInvitation(
  _prev: RevokeState,
  formData: FormData,
): Promise<RevokeState> {
  const invitationId = z
    .string()
    .uuid()
    .safeParse(formData.get("invitationId"));
  if (!invitationId.success) return { error: "철회할 초대를 찾지 못했습니다." };

  const { supabase, owner } = await requireOwner();
  if (!owner) return { error: FORBIDDEN };

  const { error } = await supabase.rpc("revoke_invitation", {
    p_invitation_id: invitationId.data,
  });
  if (error) {
    if (error.code === "42501")
      return { error: "이미 사용되었거나 철회할 수 없는 초대입니다." };
    console.error("초대 철회 실패", error.code);
    return { error: "초대를 철회하지 못했습니다. 잠시 후 다시 시도해 주세요." };
  }
  revalidatePath("/settings/team");
  return { error: null };
}

"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { z } from "zod";
import { INVITE_COOKIE } from "@/lib/invitations/cookie";
import {
  INVITATION_TOKEN_PATTERN,
  hashInvitationToken,
} from "@/lib/invitations/token";
import { serverEnv } from "@/lib/server-env";
import { createClient } from "@/lib/supabase/server";

export type AuthFormState = { error: string | null };

const tokenSchema = z.string().regex(INVITATION_TOKEN_PATTERN);
const emailSchema = z.string().trim().toLowerCase().email().max(255);

const SEND_FAILED =
  "로그인 메일을 보내지 못했습니다. 잠시 후 다시 시도해 주세요.";

/** 초대 확인 후: 초대받은 이메일로 매직 링크를 보낸다. 토큰 해시는 HttpOnly 쿠키로만 보관한다. */
export async function startInvitationSignIn(
  _prev: AuthFormState,
  formData: FormData,
): Promise<AuthFormState> {
  const token = tokenSchema.safeParse(formData.get("token"));
  if (!token.success) {
    return {
      error:
        "유효하지 않은 초대 링크입니다. 전달받은 주소를 다시 확인해 주세요.",
    };
  }
  const tokenHash = hashInvitationToken(
    token.data,
    serverEnv.invitationTokenSalt(),
  );

  const supabase = await createClient();
  const { data, error } = await supabase
    .rpc("inspect_invitation", { p_token_hash: tokenHash })
    .single();
  if (error) {
    console.error("초대 확인 실패", error.code);
    return {
      error: "초대 정보를 확인하지 못했습니다. 잠시 후 다시 시도해 주세요.",
    };
  }
  if (data.status !== "valid" || !data.email) {
    redirect(`/auth/verify?error=${data.status}`);
  }

  (await cookies()).set(INVITE_COOKIE.name, tokenHash, INVITE_COOKIE.options);

  const { error: otpError } = await supabase.auth.signInWithOtp({
    email: data.email,
    options: {
      emailRedirectTo: `${serverEnv.appUrl()}/auth/callback`,
      shouldCreateUser: true,
    },
  });
  if (otpError) {
    console.error("초대 매직 링크 발송 실패", otpError.code ?? otpError.status);
    return { error: SEND_FAILED };
  }
  redirect("/auth/verify?sent=1");
}

/** 이미 참여한 사용자의 재로그인: 기존 계정에만 매직 링크를 보낸다. */
export async function sendLoginLink(
  _prev: AuthFormState,
  formData: FormData,
): Promise<AuthFormState> {
  const email = emailSchema.safeParse(formData.get("email"));
  if (!email.success) {
    return { error: "이메일 주소 형식을 확인해 주세요." };
  }

  const supabase = await createClient();
  const { error } = await supabase.auth.signInWithOtp({
    email: email.data,
    options: {
      emailRedirectTo: `${serverEnv.appUrl()}/auth/callback`,
      shouldCreateUser: false,
    },
  });
  // 가입되지 않은 이메일인지 여부는 알려주지 않는다(계정 존재 여부 노출 방지).
  if (
    error &&
    error.code !== "otp_disabled" &&
    error.code !== "signup_disabled"
  ) {
    console.error("로그인 매직 링크 발송 실패", error.code ?? error.status);
    return { error: SEND_FAILED };
  }
  redirect("/auth/verify?sent=1");
}

export async function signOut(): Promise<void> {
  const supabase = await createClient();
  const { error } = await supabase.auth.signOut();
  if (error) {
    console.error("로그아웃 실패", error.code ?? error.status);
    throw new Error("로그아웃하지 못했습니다");
  }
  redirect("/auth/verify");
}

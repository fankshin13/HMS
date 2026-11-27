import { type NextRequest, NextResponse } from "next/server";
import { safeNextPath } from "@/lib/auth/redirect";
import { INVITE_COOKIE } from "@/lib/invitations/cookie";
import { createClient } from "@/lib/supabase/server";

/** 매직 링크 복귀 지점: 코드를 세션으로 교환하고, 초대 진행 중이면 초대를 수락한다. */
export async function GET(request: NextRequest) {
  const url = request.nextUrl;
  const toVerify = (error: string) =>
    NextResponse.redirect(new URL(`/auth/verify?error=${error}`, url.origin));

  const code = url.searchParams.get("code");
  if (!code) return toVerify("link_failed");

  const supabase = await createClient();
  const { error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) {
    console.error("매직 링크 세션 교환 실패", error.code ?? error.status);
    return toVerify("link_failed");
  }

  const tokenHash = request.cookies.get(INVITE_COOKIE.name)?.value;
  if (!tokenHash) {
    return NextResponse.redirect(
      new URL(safeNextPath(url.searchParams.get("next")), url.origin),
    );
  }

  const { data, error: acceptError } = await supabase
    .rpc("accept_invitation", { p_token_hash: tokenHash })
    .single();
  const response =
    acceptError || !data
      ? toVerify("accept_failed")
      : data.status === "accepted"
        ? NextResponse.redirect(new URL("/dashboard", url.origin))
        : toVerify(data.status);
  if (acceptError) console.error("초대 수락 실패", acceptError.code);

  response.cookies.delete({
    name: INVITE_COOKIE.name,
    path: INVITE_COOKIE.options.path,
  });
  return response;
}

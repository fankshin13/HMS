/** 매직 링크 왕복 동안 초대 토큰 해시를 보관하는 쿠키. JavaScript 에서 읽을 수 없다. */
export const INVITE_COOKIE = {
  name: "invite_token_hash",
  options: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/auth",
    maxAge: 60 * 60,
  },
};

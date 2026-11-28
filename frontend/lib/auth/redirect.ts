/** 로그인 후 이동 경로. 같은 사이트의 상대 경로만 허용해 외부 주소로의 리다이렉트를 막는다. */
export function safeNextPath(
  next: string | null | undefined,
  fallback = "/dashboard",
): string {
  if (
    !next ||
    !next.startsWith("/") ||
    next.startsWith("//") ||
    next.includes("\\")
  ) {
    return fallback;
  }
  return next;
}

// 브라우저에도 노출되는 공개 설정. Supabase publishable(anon) 키는 공개용으로 문서화된 값이다.
function required(name: string, value: string | undefined): string {
  if (!value) {
    throw new Error(`환경 변수 ${name} 이(가) 설정되지 않았습니다`);
  }
  return value;
}

export const publicEnv = {
  supabaseUrl: () =>
    required("NEXT_PUBLIC_SUPABASE_URL", process.env.NEXT_PUBLIC_SUPABASE_URL),
  supabasePublishableKey: () =>
    required(
      "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY",
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY,
    ),
};

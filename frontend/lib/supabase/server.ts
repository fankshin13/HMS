import "server-only";

import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import type { Database } from "@/lib/database.types";
import { publicEnv } from "@/lib/env";

/** 서버 컴포넌트·서버 액션·라우트 핸들러용 Supabase 클라이언트 (사용자 세션 쿠키 사용) */
export async function createClient() {
  const cookieStore = await cookies();
  return createServerClient<Database>(
    publicEnv.supabaseUrl(),
    publicEnv.supabasePublishableKey(),
    {
      cookies: {
        getAll: () => cookieStore.getAll(),
        setAll: (cookiesToSet) => {
          try {
            for (const { name, value, options } of cookiesToSet) {
              cookieStore.set(name, value, options);
            }
          } catch {
            // 서버 컴포넌트 렌더 중에는 쿠키를 쓸 수 없다. 세션 갱신은 proxy.ts 가 담당한다.
          }
        },
      },
    },
  );
}

/** 검증된 로그인 사용자 ID. 세션이 없거나 유효하지 않으면 null */
export async function getAuthUserId(
  supabase: Awaited<ReturnType<typeof createClient>>,
): Promise<string | null> {
  const { data, error } = await supabase.auth.getClaims();
  if (error || !data) return null;
  return data.claims.sub;
}

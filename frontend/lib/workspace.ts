import "server-only";

import type { createClient } from "@/lib/supabase/server";

type Supabase = Awaited<ReturnType<typeof createClient>>;

export type Membership = {
  tenantId: string;
  tenantName: string;
  role: "owner" | "operator" | "viewer";
  name: string;
  email: string;
};

/** 로그인 사용자의 활성 멤버십. RLS 로 본인 테넌트만 조회된다. (테넌트 전환 UI 전까지는 첫 번째만 사용) */
export async function getMembership(
  supabase: Supabase,
  authUserId: string,
): Promise<Membership | null> {
  const { data, error } = await supabase
    .from("users")
    .select("tenant_id, role, name, email, tenants(name)")
    .eq("auth_user_id", authUserId)
    .eq("status", "active")
    .order("created_at")
    .limit(1)
    .maybeSingle();
  if (error) {
    console.error("멤버십 조회 실패", error.code);
    throw new Error("워크스페이스 정보를 불러오지 못했습니다");
  }
  if (!data || !data.tenants) return null;
  return {
    tenantId: data.tenant_id,
    tenantName: data.tenants.name,
    role: data.role,
    name: data.name,
    email: data.email,
  };
}

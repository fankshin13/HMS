import "server-only";

import { redirect } from "next/navigation";
import { createClient, getAuthUserId } from "@/lib/supabase/server";
import { type Membership, getMembership } from "@/lib/workspace";

/** 페이지용: 로그인·멤버십을 확인하고 허용 역할이면 멤버십을, 아니면 null 을 돌려준다. */
export async function getMembershipWithRole(
  roles: Membership["role"][],
): Promise<Membership | null> {
  const supabase = await createClient();
  const userId = await getAuthUserId(supabase);
  if (!userId) redirect("/auth/verify");
  const membership = await getMembership(supabase, userId);
  return membership && roles.includes(membership.role) ? membership : null;
}

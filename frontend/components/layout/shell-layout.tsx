import type { ReactNode } from "react";
import { createClient, getAuthUserId } from "@/lib/supabase/server";
import { getMembership } from "@/lib/workspace";
import { Header } from "./header";
import { Sidebar } from "./sidebar";

export async function ShellLayout({ children }: { children: ReactNode }) {
  const supabase = await createClient();
  const userId = await getAuthUserId(supabase);
  const membership = userId ? await getMembership(supabase, userId) : null;
  const workspaceName = membership?.tenantName ?? null;
  const account = membership
    ? { name: membership.name, email: membership.email }
    : null;

  return (
    <div className="min-h-dvh">
      <Sidebar workspaceName={workspaceName} />
      <div className="flex min-h-dvh min-w-0 flex-col lg:pl-64">
        <Header account={account} workspaceName={workspaceName} />
        <main className="min-w-0 flex-1 p-4 sm:p-6">{children}</main>
      </div>
    </div>
  );
}

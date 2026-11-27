import { ShieldX, Users } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";
import { InviteDialog } from "@/components/team/invite-dialog";
import { RevokeButton } from "@/components/team/revoke-button";
import { ROLE_LABELS, STATUS_LABELS, formatSeoulDateTime } from "@/lib/format";
import { createClient, getAuthUserId } from "@/lib/supabase/server";
import { getMembership } from "@/lib/workspace";

export const metadata: Metadata = { title: "팀원 관리" };

const DESCRIPTION =
  "함께 진단할 팀원을 확인하고, 1회용 만료형 초대 링크를 발급합니다.";

export default async function TeamPage() {
  const supabase = await createClient();
  const userId = await getAuthUserId(supabase);
  if (!userId) redirect("/auth/verify");

  const membership = await getMembership(supabase, userId);
  if (membership?.role !== "owner") {
    return (
      <>
        <PageHeader title="팀원 및 초대 관리" description={DESCRIPTION} />
        <EmptyState
          icon={ShieldX}
          title="접근 권한이 없습니다"
          description="팀원 관리는 워크스페이스 소유자만 사용할 수 있습니다. 필요한 경우 소유자에게 요청해 주세요."
        />
      </>
    );
  }

  const [members, invitations] = await Promise.all([
    supabase
      .from("users")
      .select("id, name, email, role, status")
      .eq("tenant_id", membership.tenantId)
      .neq("status", "invited")
      .order("created_at"),
    supabase
      .from("invitations")
      .select("id, expires_at, users(name, email, role)")
      .eq("tenant_id", membership.tenantId)
      .is("used_at", null)
      .gt("expires_at", new Date().toISOString())
      .order("created_at", { ascending: false }),
  ]);
  if (members.error || invitations.error) {
    console.error(
      "팀원 목록 조회 실패",
      members.error?.code ?? invitations.error?.code,
    );
    throw new Error("팀원 목록을 불러오지 못했습니다");
  }

  const pending = invitations.data.flatMap((invitation) =>
    invitation.users
      ? [
          {
            ...invitation.users,
            id: invitation.id,
            expiresAt: invitation.expires_at,
          },
        ]
      : [],
  );
  const onlyOwner = members.data.length <= 1 && pending.length === 0;

  return (
    <>
      <PageHeader
        title="팀원 및 초대 관리"
        description={DESCRIPTION}
        actions={<InviteDialog />}
      />

      {onlyOwner ? (
        <EmptyState
          icon={Users}
          title="초대된 팀원이 없습니다"
          description="함께 진단을 수행할 보안 담당자나 컨설턴트에게 초대 링크를 전달해 보세요."
          action={<InviteDialog label="팀원 초대하기" />}
        />
      ) : (
        <div className="flex flex-col gap-6">
          <section
            aria-labelledby="pending-title"
            className="flex flex-col gap-2"
          >
            <h2 id="pending-title" className="text-h3">
              대기 중인 초대{" "}
              <span className="text-muted-foreground">{pending.length}</span>
            </h2>
            {pending.length === 0 ? (
              <p className="text-body text-muted-foreground">
                대기 중인 초대가 없습니다.
              </p>
            ) : (
              <ul className="flex flex-col divide-y divide-border rounded-md border border-border">
                {pending.map((invite) => (
                  <li
                    key={invite.id}
                    className="flex flex-col gap-2 p-3 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="flex min-w-0 flex-col">
                      <span className="font-medium">
                        {invite.name} · {ROLE_LABELS[invite.role]}
                      </span>
                      <span className="break-all text-muted-foreground">
                        {invite.email}
                      </span>
                      <span className="text-caption text-muted-foreground">
                        만료 {formatSeoulDateTime(invite.expiresAt)}
                      </span>
                    </div>
                    <RevokeButton
                      invitationId={invite.id}
                      email={invite.email}
                    />
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section
            aria-labelledby="members-title"
            className="flex flex-col gap-2"
          >
            <h2 id="members-title" className="text-h3">
              팀원{" "}
              <span className="text-muted-foreground">
                {members.data.length}
              </span>
            </h2>
            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full min-w-[480px] text-left text-body">
                <thead className="bg-card text-muted-foreground">
                  <tr>
                    <th scope="col" className="px-3 py-2 font-medium">
                      이름
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      이메일
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      역할
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      상태
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {members.data.map((member) => (
                    <tr key={member.id}>
                      <td className="px-3 py-2">{member.name}</td>
                      <td className="px-3 py-2 break-all">{member.email}</td>
                      <td className="px-3 py-2">{ROLE_LABELS[member.role]}</td>
                      <td className="px-3 py-2">
                        {STATUS_LABELS[member.status]}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </>
  );
}

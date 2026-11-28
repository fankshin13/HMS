import { MailCheck, ShieldCheck, ShieldX } from "lucide-react";
import type { Metadata } from "next";
import type { ReactNode } from "react";
import { AcceptInvitationForm } from "@/components/auth/accept-invitation-form";
import { LoginForm } from "@/components/auth/login-form";
import { StripTokenFromUrl } from "@/components/auth/strip-token-from-url";
import {
  INVITATION_MESSAGES,
  type InvitationProblem,
  toInvitationProblem,
} from "@/lib/invitations/status";
import {
  INVITATION_TOKEN_PATTERN,
  hashInvitationToken,
} from "@/lib/invitations/token";
import { serverEnv } from "@/lib/server-env";
import { ROLE_LABELS } from "@/lib/format";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = {
  title: "초대 확인",
  referrer: "no-referrer",
};

function Card({
  icon,
  title,
  children,
}: {
  icon: ReactNode;
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="flex w-full max-w-sm flex-col items-center gap-4 rounded-md border border-border bg-card p-6 text-center">
      {icon}
      <h1 className="text-h2">{title}</h1>
      {children}
    </section>
  );
}

function LoginSection() {
  return (
    <div className="flex w-full flex-col gap-3 border-t border-border pt-4">
      <h2 className="text-h3">이미 참여한 계정으로 로그인</h2>
      <LoginForm />
    </div>
  );
}

type SearchParams = Promise<{ token?: string; error?: string; sent?: string }>;

export default async function VerifyPage({
  searchParams,
}: {
  searchParams: SearchParams;
}) {
  const params = await searchParams;

  if (params.sent) {
    return (
      <Card
        icon={<MailCheck aria-hidden="true" className="size-8 text-primary" />}
        title="메일함을 확인하세요"
      >
        <p role="status" className="text-body text-muted-foreground">
          로그인 링크를 보냈습니다. 가입된 이메일이라면 몇 분 안에 도착합니다.
          이 브라우저에서 메일의 링크를 열어 주세요.
        </p>
      </Card>
    );
  }

  const errorProblem = toInvitationProblem(params.error);
  const found =
    !errorProblem && params.token !== undefined
      ? await lookup(params.token)
      : null;
  const problem =
    errorProblem ?? (found && !found.invitation ? found.problem : null);

  if (problem) {
    const message = INVITATION_MESSAGES[problem];
    return (
      <Card
        icon={
          <ShieldX aria-hidden="true" className="size-8 text-status-danger" />
        }
        title={message.title}
      >
        <StripTokenFromUrl />
        <p className="text-body text-muted-foreground">{message.description}</p>
        <LoginSection />
      </Card>
    );
  }

  if (found?.invitation && params.token !== undefined) {
    const { invitation } = found;
    return (
      <Card
        icon={
          <ShieldCheck aria-hidden="true" className="size-8 text-primary" />
        }
        title="워크스페이스 초대"
      >
        <StripTokenFromUrl />
        <dl className="grid w-full grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-left text-body">
          <dt className="text-muted-foreground">워크스페이스</dt>
          <dd className="font-medium">{invitation.tenantName}</dd>
          <dt className="text-muted-foreground">이름</dt>
          <dd>{invitation.userName}</dd>
          <dt className="text-muted-foreground">이메일</dt>
          <dd className="break-all">{invitation.email}</dd>
          <dt className="text-muted-foreground">역할</dt>
          <dd>{ROLE_LABELS[invitation.role]}</dd>
        </dl>
        <AcceptInvitationForm token={params.token} />
      </Card>
    );
  }

  return (
    <Card
      icon={<ShieldCheck aria-hidden="true" className="size-8 text-primary" />}
      title="로그인"
    >
      <p className="text-body text-muted-foreground">
        처음 오셨다면 관리자에게 받은 초대 링크로 접속하세요. 이미 참여했다면
        이메일로 로그인 링크를 받을 수 있습니다.
      </p>
      <LoginForm />
    </Card>
  );
}

type Invitation = {
  tenantName: string;
  userName: string;
  email: string;
  role: keyof typeof ROLE_LABELS;
};
type Lookup =
  | { invitation: Invitation; problem: null }
  | { invitation: null; problem: InvitationProblem };

async function lookup(token: string): Promise<Lookup> {
  if (!INVITATION_TOKEN_PATTERN.test(token))
    return { invitation: null, problem: "invalid" };
  const supabase = await createClient();
  const { data, error } = await supabase
    .rpc("inspect_invitation", {
      p_token_hash: hashInvitationToken(token, serverEnv.invitationTokenSalt()),
    })
    .single();
  if (error) {
    console.error("초대 확인 실패", error.code);
    throw new Error("초대 정보를 확인하지 못했습니다");
  }
  if (
    data.status === "valid" &&
    data.tenant_name &&
    data.user_name &&
    data.email &&
    data.role
  ) {
    return {
      invitation: {
        tenantName: data.tenant_name,
        userName: data.user_name,
        email: data.email,
        role: data.role,
      },
      problem: null,
    };
  }
  return {
    invitation: null,
    problem: toInvitationProblem(data.status) ?? "invalid",
  };
}

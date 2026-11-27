import { ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import { PendingFeatureButton } from "@/components/common/pending-feature";

export const metadata: Metadata = { title: "초대 확인" };

export default function VerifyPage() {
  return (
    <section className="flex w-full max-w-sm flex-col items-center gap-4 rounded-md border border-border bg-card p-6 text-center">
      <ShieldCheck aria-hidden="true" className="size-8 text-primary" />
      <h1 className="text-h2">초대 링크 확인</h1>
      <p className="text-body text-muted-foreground">
        관리자에게 받은 초대 링크로 접속하면 워크스페이스 작업 세션이
        시작됩니다.
      </p>
      <PendingFeatureButton>세션 진입</PendingFeatureButton>
    </section>
  );
}

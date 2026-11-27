import { Users } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";
import { PendingFeatureButton } from "@/components/common/pending-feature";

export const metadata: Metadata = { title: "팀원 관리" };

export default function TeamPage() {
  return (
    <>
      <PageHeader
        title="팀원 및 초대 관리"
        description="함께 진단할 팀원을 확인하고, 1회용 만료형 초대 링크를 발급합니다."
      />
      <EmptyState
        icon={Users}
        title="등록된 팀원이 없습니다"
        description="초대 링크를 발급하여 작업자를 추가하세요."
        action={
          <PendingFeatureButton>팀원 초대 링크 발급</PendingFeatureButton>
        }
      />
    </>
  );
}

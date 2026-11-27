import { SlidersHorizontal } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";
import { PendingFeatureButton } from "@/components/common/pending-feature";

export const metadata: Metadata = { title: "위험도 정책" };

export default function RiskPolicyPage() {
  return (
    <>
      <PageHeader
        title="위험도 산정 정책"
        description="기밀성·완전성·가용성 가중치와 긴급·경고·주의 등급 기준 점수를 설정합니다."
      />
      <EmptyState
        icon={SlidersHorizontal}
        title="설정된 커스텀 정책이 없습니다"
        description="기본 가중치(기밀성·완전성·가용성 3점 척도)가 적용 중입니다."
        action={<PendingFeatureButton>가중치 정책 저장</PendingFeatureButton>}
      />
    </>
  );
}

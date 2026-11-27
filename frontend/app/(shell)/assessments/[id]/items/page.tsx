import { ListChecks } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";

export const metadata: Metadata = { title: "점검 항목" };

export default function AssessmentItemsPage() {
  return (
    <>
      <PageHeader
        title="점검 항목 상세"
        description="항목별 자동 판정 결과를 확인하고, 예외 항목은 사유와 함께 판정을 수정합니다."
      />
      <EmptyState
        icon={ListChecks}
        title="점검 항목 결과 데이터가 없습니다"
        description="진단 분석이 끝나면 계정·파일·서비스·패치·로그 관리 항목이 이곳에 표시됩니다."
      />
    </>
  );
}

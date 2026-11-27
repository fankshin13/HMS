import { FileText } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";
import { PendingFeatureButton } from "@/components/common/pending-feature";

export const metadata: Metadata = { title: "보고서" };

export default function AssessmentReportsPage() {
  return (
    <>
      <PageHeader
        title="3종 보고서"
        description="상세 결과 보고서, 경영진용 결과 보고서, 위험평가 및 조치계획 보고서를 DOCX·PDF로 내려받습니다."
      />
      <EmptyState
        icon={FileText}
        title="생성 완료된 보고서가 없습니다"
        description="먼저 진단 차수 분석을 완료해 주세요."
        action={
          <PendingFeatureButton>3종 보고서 일괄 다운로드</PendingFeatureButton>
        }
      />
    </>
  );
}

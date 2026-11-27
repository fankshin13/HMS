import { Upload } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";
import { PendingFeatureButton } from "@/components/common/pending-feature";

export const metadata: Metadata = { title: "신규 진단" };

export default function NewAssessmentPage() {
  return (
    <>
      <PageHeader
        title="신규 진단 차수 시작"
        description="점검 스크립트 실행 결과를 업로드하면 호스트와 OS 정보를 자동으로 확인합니다."
      />
      <EmptyState
        icon={Upload}
        title="점검 결과 파일을 이곳에 끌어다 놓으세요"
        description="지원 형식: .txt, .log, .zip"
        action={<PendingFeatureButton>업로드 시작</PendingFeatureButton>}
      />
    </>
  );
}

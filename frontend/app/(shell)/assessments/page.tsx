import { ClipboardList, Plus } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";

export const metadata: Metadata = { title: "진단 차수" };

export default function AssessmentsPage() {
  const newAssessment = (
    <Link href="/assessments/new" className={buttonStyles.primary}>
      <Plus aria-hidden="true" className="size-4" />새 진단 차수 등록
    </Link>
  );
  return (
    <>
      <PageHeader
        title="진단 차수"
        description="진행 중이거나 완료된 취약점 진단 차수를 확인합니다."
        actions={newAssessment}
      />
      <EmptyState
        icon={ClipboardList}
        title="진행된 취약점 진단 차수가 없습니다"
        description="스크립트 결과 파일을 업로드하여 첫 진단 차수를 시작하세요."
        action={newAssessment}
      />
    </>
  );
}

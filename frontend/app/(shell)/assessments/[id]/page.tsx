import { ClipboardCheck, FileText, ListChecks } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";

export const metadata: Metadata = { title: "진단 결과" };

export default async function AssessmentPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const base = `/assessments/${encodeURIComponent(id)}`;
  return (
    <>
      <PageHeader
        title="진단 결과"
        description="호스트별 취약점 현황과 위험 점수를 확인합니다."
        actions={
          <>
            <Link href={`${base}/items`} className={buttonStyles.secondary}>
              <ListChecks aria-hidden="true" className="size-4" />
              점검 항목 상세 열람
            </Link>
            <Link href={`${base}/reports`} className={buttonStyles.primary}>
              <FileText aria-hidden="true" className="size-4" />
              3종 보고서 생성·다운로드
            </Link>
          </>
        }
      />
      <EmptyState
        icon={ClipboardCheck}
        title="진단 데이터가 없습니다"
        description="선택된 진단 차수의 데이터가 존재하지 않거나 처리 대기 중입니다."
      />
    </>
  );
}

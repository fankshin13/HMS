import { LayoutDashboard, Plus } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";

export const metadata: Metadata = { title: "대시보드" };

export default function DashboardPage() {
  const newAssessment = (
    <Link href="/assessments/new" className={buttonStyles.primary}>
      <Plus aria-hidden="true" className="size-4" />
      신규 진단 차수 시작
    </Link>
  );
  return (
    <>
      <PageHeader
        title="전사 진단 개요"
        description="전체 자산의 양호·취약 현황과 고위험 자산을 한눈에 확인합니다."
        actions={newAssessment}
      />
      <EmptyState
        icon={LayoutDashboard}
        title="등록된 진단 내역이 없습니다"
        description="신규 진단 차수를 시작하여 스크립트 결과를 분석해 보세요."
        action={newAssessment}
      />
    </>
  );
}

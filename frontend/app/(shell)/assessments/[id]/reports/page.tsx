import { ArrowLeft, FileText } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { z } from "zod";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";
import { Forbidden } from "@/components/common/forbidden";
import { PageHeader } from "@/components/common/page-header";
import { ReportCenter } from "@/components/reports/report-center";
import { getMembershipWithRole } from "@/lib/auth/require-role";
import { loadReportStatus } from "@/lib/reports/status";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = { title: "보고서" };

export default async function AssessmentReportsPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  if (!z.string().uuid().safeParse(id).success) notFound();
  const membership = await getMembershipWithRole([
    "owner",
    "operator",
    "viewer",
  ]);
  if (!membership)
    return (
      <Forbidden description="워크스페이스 구성원만 보고서를 볼 수 있습니다." />
    );

  const supabase = await createClient();
  const { data: run, error } = await supabase
    .from("assessment_runs")
    .select("id, title, status, total_assets, vulnerable_items_count")
    .eq("id", id)
    .maybeSingle();
  if (error) {
    console.error("진단 차수 조회 실패", error.code);
    throw new Error("보고서 정보를 불러오지 못했습니다");
  }
  if (!run) notFound();

  const resultsHref = `/assessments/${id}`;
  const header = (
    <PageHeader
      title={`3종 보고서 · ${run.title}`}
      description={`자산 ${run.total_assets.toLocaleString("ko-KR")}대 · 취약 항목 ${run.vulnerable_items_count.toLocaleString("ko-KR")}건 · 상세 결과 보고서, 결과 보고서, 위험평가 결과 및 조치계획서를 DOCX·PDF로 한 번에 만듭니다.`}
      actions={
        <Link href={resultsHref} className={buttonStyles.secondary}>
          <ArrowLeft aria-hidden="true" className="size-4" />
          진단 결과로
        </Link>
      }
    />
  );

  if (run.status !== "completed") {
    return (
      <>
        {header}
        <EmptyState
          icon={FileText}
          title="진단 분석이 완료되지 않아 보고서를 생성할 수 없습니다."
          description="분석과 위험도 산정이 끝나면 3종 보고서를 생성할 수 있습니다."
          action={
            <Link href={resultsHref} className={buttonStyles.primary}>
              진단 대시보드로 이동
            </Link>
          }
        />
      </>
    );
  }

  const status = await loadReportStatus(supabase, id);
  if (!status) notFound();
  return (
    <>
      {header}
      <ReportCenter
        runId={id}
        initial={status}
        canGenerate={membership.role !== "viewer"}
      />
    </>
  );
}

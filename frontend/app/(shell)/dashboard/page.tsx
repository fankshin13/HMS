import {
  ClipboardList,
  Info,
  LayoutDashboard,
  OctagonAlert,
  Plus,
  Server,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { BarList } from "@/components/charts/bar-list";
import { ColumnChart } from "@/components/charts/column-chart";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";
import { Forbidden } from "@/components/common/forbidden";
import { PageHeader } from "@/components/common/page-header";
import { CATEGORY_LABELS } from "@/lib/assessments/labels";
import { getMembershipWithRole } from "@/lib/auth/require-role";
import { complianceRate, dashboardSchema } from "@/lib/dashboard/summary";
import { formatSeoulDateTime } from "@/lib/format";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = { title: "대시보드" };

const shortDate = new Intl.DateTimeFormat("ko-KR", {
  timeZone: "Asia/Seoul",
  month: "numeric",
  day: "numeric",
});

function categoryLabel(key: string): string {
  return key in CATEGORY_LABELS
    ? CATEGORY_LABELS[key as keyof typeof CATEGORY_LABELS]
    : key;
}

export default async function DashboardPage() {
  const membership = await getMembershipWithRole([
    "owner",
    "operator",
    "viewer",
  ]);
  if (!membership)
    return (
      <Forbidden description="워크스페이스 구성원만 대시보드를 볼 수 있습니다." />
    );

  const supabase = await createClient();
  const { data, error } = await supabase.rpc("get_dashboard_summary", {
    p_tenant_id: membership.tenantId,
  });
  if (error) {
    console.error("대시보드 조회 실패", error.code);
    throw new Error("대시보드를 불러오지 못했습니다");
  }
  const parsed = dashboardSchema.safeParse(data);
  if (!parsed.success)
    throw new Error("대시보드 데이터 형식이 올바르지 않습니다");
  const summary = parsed.data;
  const canUpload = membership.role !== "viewer";

  const newAssessment = canUpload ? (
    <Link href="/assessments/new" className={buttonStyles.primary}>
      <Plus aria-hidden="true" className="size-4" />
      신규 진단 차수 시작
    </Link>
  ) : undefined;
  const header = (
    <PageHeader
      title="전사 진단 개요"
      description="가장 최근 완료된 진단을 기준으로 양호·취약 현황과 고위험 자산을 보여 줍니다."
      actions={newAssessment}
    />
  );

  const latest = summary.latest;
  if (!latest) {
    return (
      <>
        {header}
        <EmptyState
          icon={LayoutDashboard}
          title={
            summary.in_progress_count > 0
              ? "진단을 분석하는 중입니다"
              : "완료된 진단 내역이 없습니다"
          }
          description={
            summary.in_progress_count > 0
              ? "분석이 끝나면 이곳에 진단 현황이 표시됩니다."
              : "신규 진단 차수를 시작하여 스크립트 결과를 분석해 보세요."
          }
          action={newAssessment}
        />
      </>
    );
  }

  const rate = complianceRate(latest.good, latest.vulnerable);
  const tiles = [
    {
      label: "관리 자산",
      value: `${summary.asset_count.toLocaleString("ko-KR")}대`,
      icon: Server,
    },
    {
      label: "진단 차수",
      value: `${summary.run_count.toLocaleString("ko-KR")}회`,
      note:
        summary.in_progress_count > 0
          ? `분석 중 ${summary.in_progress_count}`
          : undefined,
      icon: ClipboardList,
    },
    {
      label: "양호율",
      value: `${rate}%`,
      note: "해당없음 제외",
      icon: ShieldCheck,
    },
    {
      label: "취약 항목",
      value: `${latest.vulnerable.toLocaleString("ko-KR")}건`,
      note: `점검 ${latest.checks.toLocaleString("ko-KR")}건 중`,
      icon: TriangleAlert,
    },
  ];
  const risks = [
    {
      label: "긴급",
      value: latest.critical,
      icon: OctagonAlert,
      tone: "text-status-danger",
      note: `${summary.critical_threshold}점 이상 · 7일 이내`,
    },
    {
      label: "경고",
      value: latest.warning,
      icon: TriangleAlert,
      tone: "text-status-warning",
      note: `${summary.warning_threshold}점 이상 · 30일 이내`,
    },
    {
      label: "주의",
      value: latest.caution,
      icon: Info,
      tone: "text-muted-foreground",
      note: "90일 이내",
    },
  ];

  return (
    <>
      {header}
      <p className="mb-4 text-body text-muted-foreground">
        기준 진단:{" "}
        <Link
          href={`/assessments/${latest.id}`}
          className="font-medium text-foreground underline"
        >
          {latest.title}
        </Link>{" "}
        · {formatSeoulDateTime(latest.created_at)} · 자산 {latest.total_assets}
        대
      </p>

      <section
        aria-label="핵심 지표"
        className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4"
      >
        {tiles.map((tile) => (
          <div
            key={tile.label}
            className="flex flex-col gap-1 rounded-md border border-border bg-card p-3"
          >
            <span className="flex items-center gap-1 text-caption text-muted-foreground">
              <tile.icon aria-hidden="true" className="size-4" />
              {tile.label}
            </span>
            <span className="text-h2">{tile.value}</span>
            {tile.note && (
              <span className="text-caption text-muted-foreground">
                {tile.note}
              </span>
            )}
          </div>
        ))}
      </section>

      <section
        aria-labelledby="risk-title"
        className="mb-6 flex flex-col gap-3"
      >
        <h2 id="risk-title" className="text-h3">
          위험 등급별 취약 항목
        </h2>
        <div className="grid gap-3 sm:grid-cols-3">
          {risks.map((risk) => (
            <Link
              key={risk.label}
              href={`/assessments/${latest.id}/items?status=vulnerable`}
              className="flex min-h-11 flex-col gap-1 rounded-md border border-border bg-card p-3 hover:bg-border"
            >
              <span
                className={`flex items-center gap-1 font-medium ${risk.tone}`}
              >
                <risk.icon aria-hidden="true" className="size-4" />
                {risk.label}
              </span>
              <span className="text-h2">
                {risk.value.toLocaleString("ko-KR")}건
              </span>
              <span className="text-caption text-muted-foreground">
                {risk.note}
              </span>
            </Link>
          ))}
        </div>
      </section>

      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <section className="rounded-md border border-border bg-card p-4">
          <ColumnChart
            title="최근 진단 양호율 추이"
            unit="%"
            max={100}
            data={summary.trend.map((run) => ({
              key: run.id,
              label: shortDate.format(new Date(run.created_at)),
              value: complianceRate(run.good, run.vulnerable),
              detail: `${run.title} · 취약 ${run.vulnerable}건`,
            }))}
          />
        </section>
        <section className="rounded-md border border-border bg-card p-4">
          <BarList
            title="분야별 취약 항목 수(최근 진단)"
            unit="건"
            data={summary.categories.map((c) => ({
              key: c.category,
              label: categoryLabel(c.category),
              value: c.vulnerable,
              detail: `점검 ${c.checks}건 · 양호율 ${complianceRate(c.good, c.vulnerable)}%`,
            }))}
          />
        </section>
      </div>

      <section aria-labelledby="top-assets" className="flex flex-col gap-3">
        <h2 id="top-assets" className="text-h3">
          고위험 자산(위험 점수 합계 순)
        </h2>
        {summary.top_assets.length === 0 ? (
          <p className="text-body text-muted-foreground">
            취약 항목이 있는 자산이 없습니다.
          </p>
        ) : (
          <ol className="flex flex-col divide-y divide-border rounded-md border border-border">
            {summary.top_assets.map((asset, rank) => (
              <li key={asset.asset_id}>
                <Link
                  href={`/assessments/${latest.id}/items?asset=${asset.asset_id}&status=vulnerable`}
                  className="grid min-h-11 grid-cols-[2rem_1fr_auto] items-center gap-3 px-3 py-2 hover:bg-card"
                >
                  <span className="text-caption text-muted-foreground">
                    {rank + 1}
                  </span>
                  <span className="min-w-0">
                    <span className="block truncate font-medium">
                      {asset.hostname}
                    </span>
                    <span className="block text-caption text-muted-foreground">
                      취약 {asset.vulnerable}건 · 긴급 {asset.critical}건
                    </span>
                  </span>
                  <span className="text-body font-medium">
                    {asset.score_sum.toFixed(2)}점
                  </span>
                </Link>
              </li>
            ))}
          </ol>
        )}
      </section>
    </>
  );
}

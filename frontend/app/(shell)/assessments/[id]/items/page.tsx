import { ArrowLeft, ListChecks, PencilLine } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { z } from "zod";
import { ItemActions } from "@/components/assessment/item-actions";
import { ItemEvidence } from "@/components/assessment/item-evidence";
import { ItemFilterForm } from "@/components/assessment/item-filter-form";
import { ItemStatusBadge } from "@/components/assessment/item-status-badge";
import { RiskBadge } from "@/components/assessment/risk-badge";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";
import { Forbidden } from "@/components/common/forbidden";
import { PageHeader } from "@/components/common/page-header";
import { getMembershipWithRole } from "@/lib/auth/require-role";
import {
  ITEM_PAGE_SIZE,
  type SearchParams,
  itemsHref,
  parseItemFilters,
} from "@/lib/assessments/item-filters";
import {
  CATEGORY_LABELS,
  ITEM_STATUS_LABELS,
  RISK_LABELS,
  isInProgress,
} from "@/lib/assessments/labels";
import { formatScore, riskCategory } from "@/lib/assessments/risk";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = { title: "점검 항목" };

// 타입 추론을 위해 하나의 문자열 리터럴로 둔다
const ITEM_SELECT =
  "id, item_code, auto_status, final_status, calculated_risk_score, stdout_snippet, raw_log_start_line, raw_log_end_line, assets(hostname, confidentiality_score, integrity_score, availability_score), compliance_guidelines!inner(name, category, risk_level, good_condition, vulnerable_condition, remediation_guide)";

export default async function AssessmentItemsPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: SearchParams;
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
      <Forbidden description="워크스페이스 구성원만 점검 항목을 볼 수 있습니다." />
    );
  const canEdit = membership.role !== "viewer";
  const filters = parseItemFilters(await searchParams);

  const supabase = await createClient();
  const [
    { data: run, error: runError },
    { data: summary, error: summaryError },
  ] = await Promise.all([
    supabase
      .from("assessment_runs")
      .select("id, title, status")
      .eq("id", id)
      .maybeSingle(),
    supabase.rpc("get_assessment_risk_summary", { p_run_id: id }).maybeSingle(),
  ]);
  if (runError || summaryError) {
    console.error("점검 항목 조회 실패", runError?.code ?? summaryError?.code);
    throw new Error("점검 항목을 불러오지 못했습니다");
  }
  if (!run) notFound();

  const resultsHref = `/assessments/${id}`;
  const base = `${resultsHref}/items`;
  const header = (
    <PageHeader
      title={`점검 항목 · ${run.title}`}
      description="위험 점수 = 자산 중요도(기밀성+무결성+가용성, 3~9) × 취약 등급(상 3·중 2·하 1). 예외 항목은 사유와 함께 판정을 변경할 수 있습니다."
      actions={
        <Link href={resultsHref} className={buttonStyles.secondary}>
          <ArrowLeft aria-hidden="true" className="size-4" />
          진단 결과로
        </Link>
      }
    />
  );

  if (isInProgress(run.status) || run.status === "failed") {
    return (
      <>
        {header}
        <EmptyState
          icon={ListChecks}
          title={
            run.status === "failed"
              ? "분석에 실패한 진단입니다"
              : "아직 분석 중입니다"
          }
          description="분석이 끝나면 항목별 위험 점수와 판정 변경 기능을 사용할 수 있습니다."
          action={
            <Link href={resultsHref} className={buttonStyles.primary}>
              진단 결과 화면으로 이동
            </Link>
          }
        />
      </>
    );
  }

  const thresholds = {
    critical: summary?.critical_threshold ?? 15,
    warning: summary?.warning_threshold ?? 8,
  };

  const { data: logs, error: logsError } = await supabase
    .from("diagnostic_logs")
    .select("asset_id, assets(hostname)")
    .eq("assessment_run_id", id)
    .order("file_name");
  if (logsError) {
    console.error("진단 로그 조회 실패", logsError.code);
    throw new Error("점검 항목을 불러오지 못했습니다");
  }
  const assetOptions = logs.flatMap((l) =>
    l.asset_id && l.assets
      ? [{ id: l.asset_id, hostname: l.assets.hostname }]
      : [],
  );

  let query = supabase
    .from("inspection_item_results")
    .select(ITEM_SELECT, { count: "exact" })
    .eq("assessment_run_id", id);
  if (filters.asset) query = query.eq("asset_id", filters.asset);
  if (filters.status) query = query.eq("final_status", filters.status);
  if (filters.category)
    query = query.eq("compliance_guidelines.category", filters.category);
  const from = (filters.page - 1) * ITEM_PAGE_SIZE;
  const {
    data: items,
    count,
    error,
  } = await query
    .order("calculated_risk_score", { ascending: false })
    .order("item_code")
    .order("asset_id")
    .range(from, from + ITEM_PAGE_SIZE - 1);
  if (error) {
    console.error("점검 항목 조회 실패", error.code);
    throw new Error("점검 항목을 불러오지 못했습니다");
  }

  const ids = items.map((item) => item.id);
  const { data: audits, error: auditError } = ids.length
    ? await supabase
        .from("override_audit_logs")
        .select("inspection_item_result_id")
        .in("inspection_item_result_id", ids)
    : { data: [], error: null };
  if (auditError) {
    console.error("변경 이력 조회 실패", auditError.code);
    throw new Error("점검 항목을 불러오지 못했습니다");
  }
  const overridden = new Set(audits.map((a) => a.inspection_item_result_id));

  const total = count ?? 0;
  const pages = Math.max(1, Math.ceil(total / ITEM_PAGE_SIZE));
  const pageHref = (page: number) =>
    itemsHref(base, filters, { page: String(page) });

  const cards = [
    { label: "취약 항목", value: summary?.vulnerable_count ?? 0 },
    {
      label: `긴급 (${thresholds.critical}점 이상)`,
      value: summary?.critical_count ?? 0,
    },
    {
      label: `경고 (${thresholds.warning}~${thresholds.critical}점 미만)`,
      value: summary?.warning_count ?? 0,
    },
    {
      label: `주의 (${thresholds.warning}점 미만)`,
      value: summary?.caution_count ?? 0,
    },
  ];

  return (
    <>
      {header}
      <section
        aria-label="위험 요약"
        className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4"
      >
        {cards.map((card) => (
          <div
            key={card.label}
            className="flex flex-col gap-1 rounded-md border border-border bg-card p-3"
          >
            <span className="text-caption text-muted-foreground">
              {card.label}
            </span>
            <span className="text-h2">
              {card.value.toLocaleString("ko-KR")}
            </span>
          </div>
        ))}
        <p className="col-span-2 text-caption text-muted-foreground lg:col-span-4">
          최고 위험 점수 {formatScore(Number(summary?.max_risk_score ?? 0))}점
        </p>
      </section>

      <section aria-labelledby="items-title" className="flex flex-col gap-4">
        <h2 id="items-title" className="sr-only">
          점검 항목 위험 점수
        </h2>
        <ItemFilterForm
          resetHref={base}
          filters={filters}
          assetOptions={assetOptions}
        />
        <p role="status" className="text-body text-muted-foreground">
          {total.toLocaleString("ko-KR")}건 중 {total === 0 ? 0 : from + 1}–
          {Math.min(from + ITEM_PAGE_SIZE, total)} · 위험 점수 높은 순
        </p>

        {items.length === 0 ? (
          <EmptyState
            icon={ListChecks}
            title="조건에 맞는 점검 항목이 없습니다"
            description="필터를 바꾸거나 초기화해 보세요."
            action={
              <Link href={base} className={buttonStyles.secondary}>
                필터 초기화
              </Link>
            }
          />
        ) : (
          <ul className="flex flex-col divide-y divide-border rounded-md border border-border">
            {items.map((item) => {
              const guide = item.compliance_guidelines;
              const score = Number(item.calculated_risk_score);
              const asset = item.assets;
              const isOverridden = overridden.has(item.id);
              const label = `${item.item_code} ${asset?.hostname ?? ""}`.trim();
              return (
                <li key={item.id}>
                  <details>
                    <summary className="grid min-h-11 cursor-pointer grid-cols-[4.5rem_1fr_auto] items-center gap-x-3 gap-y-1 px-3 py-2 sm:grid-cols-[4.5rem_1fr_9rem_8rem_6rem]">
                      <span className="font-mono text-caption">
                        {item.item_code}
                      </span>
                      <span className="min-w-0">
                        <span className="block font-medium">{guide.name}</span>
                        <span className="block text-caption text-muted-foreground">
                          {CATEGORY_LABELS[guide.category]} · 위험도{" "}
                          {RISK_LABELS[guide.risk_level]}
                          <span className="sm:hidden">
                            {" "}
                            · {asset?.hostname}
                          </span>
                          {isOverridden && (
                            <span className="ml-1 inline-flex items-center gap-1 text-primary">
                              <PencilLine
                                aria-hidden="true"
                                className="size-3"
                              />
                              수동 변경됨
                            </span>
                          )}
                        </span>
                        <span className="mt-1 block text-caption sm:hidden">
                          <RiskBadge
                            category={riskCategory(
                              item.final_status,
                              score,
                              thresholds,
                            )}
                            score={score}
                          />
                        </span>
                      </span>
                      <span className="hidden truncate text-body sm:block">
                        {asset?.hostname}
                      </span>
                      <span className="hidden text-body sm:block">
                        <RiskBadge
                          category={riskCategory(
                            item.final_status,
                            score,
                            thresholds,
                          )}
                          score={score}
                        />
                      </span>
                      <ItemStatusBadge status={item.final_status} />
                    </summary>
                    <div className="flex flex-col gap-3 border-t border-border bg-card px-3 py-3">
                      <p className="text-body">
                        자동 판정 {ITEM_STATUS_LABELS[item.auto_status]} → 최종
                        판정 {ITEM_STATUS_LABELS[item.final_status]}
                        {asset && (
                          <span className="block text-caption text-muted-foreground">
                            자산 중요도 기밀성 {asset.confidentiality_score} +
                            무결성 {asset.integrity_score} + 가용성{" "}
                            {asset.availability_score} ={" "}
                            {asset.confidentiality_score +
                              asset.integrity_score +
                              asset.availability_score}{" "}
                            · 위험 점수 {formatScore(score)}
                          </span>
                        )}
                      </p>
                      <ItemActions
                        runId={id}
                        itemId={item.id}
                        itemLabel={label}
                        autoStatus={item.auto_status}
                        finalStatus={item.final_status}
                        canEdit={canEdit}
                        hasHistory={isOverridden}
                      />
                      <ItemEvidence
                        snippet={item.stdout_snippet}
                        startLine={item.raw_log_start_line}
                        endLine={item.raw_log_end_line}
                        guide={guide}
                      />
                    </div>
                  </details>
                </li>
              );
            })}
          </ul>
        )}

        {pages > 1 && (
          <nav
            aria-label="페이지"
            className="flex items-center justify-between gap-2"
          >
            {filters.page > 1 ? (
              <Link
                href={pageHref(filters.page - 1)}
                className={buttonStyles.secondary}
              >
                이전
              </Link>
            ) : (
              <span />
            )}
            <span className="text-body text-muted-foreground">
              {filters.page} / {pages}
            </span>
            {filters.page < pages ? (
              <Link
                href={pageHref(filters.page + 1)}
                className={buttonStyles.secondary}
              >
                다음
              </Link>
            ) : (
              <span />
            )}
          </nav>
        )}
      </section>
    </>
  );
}

import {
  ClipboardCheck,
  FileText,
  ListChecks,
  ServerCrash,
  TriangleAlert,
} from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { z } from "zod";
import { ItemStatusBadge } from "@/components/assessment/item-status-badge";
import { ParsingProgress } from "@/components/assessment/parsing-progress";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";
import { inputStyles, labelStyles } from "@/components/common/form-styles";
import { PageHeader } from "@/components/common/page-header";
import {
  CATEGORY_LABELS,
  ITEM_STATUS_LABELS,
  RISK_LABELS,
  RUN_STATUS_LABELS,
  isInProgress,
  progressPercentage,
} from "@/lib/assessments/labels";
import type { Database } from "@/lib/database.types";
import { formatSeoulDateTime } from "@/lib/format";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = { title: "진단 결과" };

type Enums = Database["public"]["Enums"];
type SearchParams = Promise<Record<string, string | string[] | undefined>>;

const PAGE_SIZE = 50;

// 타입 추론을 위해 하나의 문자열 리터럴로 둔다
const ITEM_SELECT =
  "id, item_code, final_status, stdout_snippet, raw_log_start_line, raw_log_end_line, assets(hostname), compliance_guidelines!inner(name, category, risk_level, good_condition, vulnerable_condition, remediation_guide)";

const filtersSchema = z.object({
  tab: z.enum(["items", "quarantine"]).catch("items"),
  asset: z.string().uuid().optional().catch(undefined),
  status: z.enum(["good", "vulnerable", "na"]).optional().catch(undefined),
  category: z
    .enum([
      "account_management",
      "directory_file_management",
      "service_management",
      "patch_management",
      "log_management",
    ])
    .optional()
    .catch(undefined),
  page: z.coerce.number().int().min(1).catch(1),
});

const errorListSchema = z.array(
  z.object({
    line_number: z.number(),
    reason: z.string(),
    raw_snippet: z.string().optional(),
  }),
);
const uploadErrorSchema = z.object({
  message: z.string(),
  line: z.number().nullable().optional(),
});

function errorsOf(
  details: unknown,
): { line: number; reason: string; snippet: string }[] {
  const list = errorListSchema.safeParse(details);
  if (list.success)
    return list.data.map((e) => ({
      line: e.line_number,
      reason: e.reason,
      snippet: e.raw_snippet ?? "",
    }));
  const single = uploadErrorSchema.safeParse(details);
  if (single.success)
    return [
      { line: single.data.line ?? 0, reason: single.data.message, snippet: "" },
    ];
  return [];
}

function splitSnippet(snippet: string | null): {
  reason: string | null;
  evidence: string;
} {
  if (!snippet) return { reason: null, evidence: "" };
  const [first, ...rest] = snippet.split("\n");
  if (first?.startsWith("[판정 근거] "))
    return { reason: first.slice(8), evidence: rest.join("\n") };
  return { reason: null, evidence: snippet };
}

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export default async function AssessmentPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: SearchParams;
}) {
  const { id } = await params;
  if (!z.string().uuid().safeParse(id).success) notFound();
  const raw = await searchParams;
  const filters = filtersSchema.parse({
    tab: first(raw.tab),
    asset: first(raw.asset),
    status: first(raw.status),
    category: first(raw.category),
    page: first(raw.page),
  });

  const supabase = await createClient();
  const [
    { data: run, error: runError },
    { data: progress, error: progressError },
  ] = await Promise.all([
    supabase
      .from("assessment_runs")
      .select("id, title, status, created_at")
      .eq("id", id)
      .maybeSingle(),
    supabase.rpc("get_assessment_progress", { p_run_id: id }).maybeSingle(),
  ]);
  if (runError || progressError) {
    console.error("진단 결과 조회 실패", runError?.code ?? progressError?.code);
    throw new Error("진단 결과를 불러오지 못했습니다");
  }
  if (!run || !progress) notFound();

  const base = `/assessments/${id}`;
  const header = (
    <PageHeader
      title={run.title}
      description={`${formatSeoulDateTime(run.created_at)} 등록 · ${RUN_STATUS_LABELS[run.status]}`}
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
  );

  if (isInProgress(run.status)) {
    return (
      <>
        {header}
        <ParsingProgress
          runId={id}
          initial={{
            status: progress.status,
            progress_percentage: progressPercentage(
              progress.status,
              progress.total_assets,
              progress.processed_assets,
            ),
            total_assets: progress.total_assets,
            processed_assets: progress.processed_assets,
          }}
        />
      </>
    );
  }

  if (run.status === "failed") {
    return (
      <>
        {header}
        <EmptyState
          icon={ServerCrash}
          title="로그 파싱 중 치명적 오류가 발생했습니다"
          description="원본 파일을 읽지 못했습니다. 잠시 후 같은 파일을 다시 업로드해 새 진단 차수로 분석해 주세요."
          action={
            <Link href="/assessments/new" className={buttonStyles.primary}>
              파일 다시 업로드
            </Link>
          }
        />
      </>
    );
  }

  const { data: logs, error: logsError } = await supabase
    .from("diagnostic_logs")
    .select(
      "id, file_name, asset_id, parse_status, quarantined_error_lines, error_details, assets(hostname)",
    )
    .eq("assessment_run_id", id)
    .order("file_name");
  if (logsError) {
    console.error("진단 로그 조회 실패", logsError.code);
    throw new Error("진단 결과를 불러오지 못했습니다");
  }

  if (logs.length === 0 && progress.total_checks === 0) {
    return (
      <>
        {header}
        <EmptyState
          icon={ClipboardCheck}
          title="분석된 점검 결과가 없습니다"
          description="신규 진단 파일을 먼저 업로드해 주세요."
          action={
            <Link href="/assessments/new" className={buttonStyles.primary}>
              신규 진단 시작
            </Link>
          }
        />
      </>
    );
  }

  const quarantined = logs.filter((log) => log.parse_status !== "success");
  const healthyAssetIds = logs
    .filter((l) => l.parse_status === "success" && l.asset_id)
    .map((l) => l.asset_id ?? "");
  const assetOptions = logs.flatMap((l) =>
    l.asset_id && l.assets
      ? [{ id: l.asset_id, hostname: l.assets.hostname }]
      : [],
  );

  return (
    <>
      {header}
      <section
        aria-label="진단 요약"
        className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4"
      >
        {[
          { label: "전체 자산", value: progress.total_assets },
          { label: "정상 분석 자산", value: new Set(healthyAssetIds).size },
          { label: "수동 검토 필요", value: quarantined.length },
          { label: "취약 항목", value: progress.vulnerable_count },
        ].map((card) => (
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
          점검 {progress.total_checks.toLocaleString("ko-KR")}건 · 양호{" "}
          {progress.good_count.toLocaleString("ko-KR")} · 취약{" "}
          {progress.vulnerable_count.toLocaleString("ko-KR")} · 해당없음{" "}
          {progress.na_count.toLocaleString("ko-KR")}
        </p>
      </section>

      <nav
        aria-label="결과 보기"
        className="mb-4 flex flex-wrap gap-2 border-b border-border"
      >
        {[
          { tab: "items", label: "정상 분석 자산" },
          {
            tab: "quarantine",
            label: `수동 검토 필요 (${quarantined.length})`,
          },
        ].map((item) => {
          const active = filters.tab === item.tab;
          return (
            <Link
              key={item.tab}
              href={`${base}?tab=${item.tab}`}
              aria-current={active ? "page" : undefined}
              className={`-mb-px inline-flex min-h-11 items-center border-b-2 px-3 text-body ${
                active
                  ? "border-primary font-semibold"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              {item.label}
            </Link>
          );
        })}
      </nav>

      {filters.tab === "quarantine" ? (
        <QuarantineList base={base} logs={quarantined} />
      ) : (
        <ItemsTab
          base={base}
          runId={id}
          filters={filters}
          healthyAssetIds={healthyAssetIds}
          assetOptions={assetOptions}
        />
      )}
    </>
  );
}

type Filters = z.infer<typeof filtersSchema>;

async function ItemsTab({
  base,
  runId,
  filters,
  healthyAssetIds,
  assetOptions,
}: {
  base: string;
  runId: string;
  filters: Filters;
  healthyAssetIds: string[];
  assetOptions: { id: string; hostname: string }[];
}) {
  const supabase = await createClient();
  let query = supabase
    .from("inspection_item_results")
    .select(ITEM_SELECT, { count: "exact" })
    .eq("assessment_run_id", runId);
  query = filters.asset
    ? query.eq("asset_id", filters.asset)
    : query.in("asset_id", healthyAssetIds);
  if (filters.status) query = query.eq("final_status", filters.status);
  if (filters.category)
    query = query.eq("compliance_guidelines.category", filters.category);
  const from = (filters.page - 1) * PAGE_SIZE;
  const { data, count, error } = await query
    .order("item_code")
    .order("asset_id")
    .range(from, from + PAGE_SIZE - 1);
  if (error) {
    console.error("점검 항목 조회 실패", error.code);
    throw new Error("점검 항목을 불러오지 못했습니다");
  }
  const total = count ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const pageHref = (page: number) => {
    const params = new URLSearchParams({ tab: "items", page: String(page) });
    if (filters.asset) params.set("asset", filters.asset);
    if (filters.status) params.set("status", filters.status);
    if (filters.category) params.set("category", filters.category);
    return `${base}?${params}`;
  };

  return (
    <section aria-labelledby="items-title" className="flex flex-col gap-4">
      <h2 id="items-title" className="sr-only">
        점검 항목 판정 결과
      </h2>
      <form
        method="get"
        className="grid gap-3 sm:grid-cols-2 lg:grid-cols-[1fr_1fr_1fr_auto] lg:items-end"
      >
        <input type="hidden" name="tab" value="items" />
        <div className="flex flex-col gap-1">
          <label htmlFor="filter-asset" className={labelStyles}>
            자산
          </label>
          <select
            id="filter-asset"
            name="asset"
            defaultValue={filters.asset ?? ""}
            className={inputStyles}
          >
            <option value="">정상 분석 자산 전체</option>
            {assetOptions.map((asset) => (
              <option key={asset.id} value={asset.id}>
                {asset.hostname}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="filter-status" className={labelStyles}>
            판정
          </label>
          <select
            id="filter-status"
            name="status"
            defaultValue={filters.status ?? ""}
            className={inputStyles}
          >
            <option value="">전체</option>
            {(Object.keys(ITEM_STATUS_LABELS) as Enums["item_status"][]).map(
              (status) => (
                <option key={status} value={status}>
                  {ITEM_STATUS_LABELS[status]}
                </option>
              ),
            )}
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="filter-category" className={labelStyles}>
            분야
          </label>
          <select
            id="filter-category"
            name="category"
            defaultValue={filters.category ?? ""}
            className={inputStyles}
          >
            <option value="">전체</option>
            {(
              Object.keys(CATEGORY_LABELS) as Enums["compliance_category"][]
            ).map((category) => (
              <option key={category} value={category}>
                {CATEGORY_LABELS[category]}
              </option>
            ))}
          </select>
        </div>
        <div className="flex gap-2">
          <button type="submit" className={buttonStyles.primary}>
            적용
          </button>
          <Link href={`${base}?tab=items`} className={buttonStyles.secondary}>
            초기화
          </Link>
        </div>
      </form>

      <p role="status" className="text-body text-muted-foreground">
        {total.toLocaleString("ko-KR")}건 중 {total === 0 ? 0 : from + 1}–
        {Math.min(from + PAGE_SIZE, total)}
      </p>

      {data.length === 0 ? (
        <EmptyState
          icon={ListChecks}
          title="조건에 맞는 점검 항목이 없습니다"
          description="필터를 바꾸거나 초기화해 보세요."
          action={
            <Link href={`${base}?tab=items`} className={buttonStyles.secondary}>
              필터 초기화
            </Link>
          }
        />
      ) : (
        <ul className="flex flex-col divide-y divide-border rounded-md border border-border">
          {data.map((item) => {
            const guide = item.compliance_guidelines;
            const { reason, evidence } = splitSnippet(item.stdout_snippet);
            return (
              <li key={item.id}>
                <details className="group">
                  <summary className="grid min-h-11 cursor-pointer grid-cols-[4.5rem_1fr_auto] items-center gap-x-3 gap-y-1 px-3 py-2 sm:grid-cols-[4.5rem_1fr_10rem_6rem]">
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
                          · {item.assets?.hostname}
                        </span>
                      </span>
                    </span>
                    <span className="hidden truncate text-body sm:block">
                      {item.assets?.hostname}
                    </span>
                    <ItemStatusBadge status={item.final_status} />
                  </summary>
                  <div className="flex flex-col gap-3 border-t border-border bg-card px-3 py-3 text-body">
                    {reason && (
                      <p>
                        <span className="font-medium">판정 근거</span> {reason}
                      </p>
                    )}
                    <dl className="grid gap-1 sm:grid-cols-[6rem_1fr]">
                      <dt className="text-muted-foreground">양호 기준</dt>
                      <dd>{guide.good_condition}</dd>
                      <dt className="text-muted-foreground">취약 기준</dt>
                      <dd>{guide.vulnerable_condition}</dd>
                      <dt className="text-muted-foreground">조치 방법</dt>
                      <dd>{guide.remediation_guide}</dd>
                    </dl>
                    {evidence && (
                      <div className="flex flex-col gap-1">
                        <span className="text-caption text-muted-foreground">
                          스크립트 출력 원문 ({item.raw_log_start_line}–
                          {item.raw_log_end_line}번째 줄)
                        </span>
                        <pre className="max-h-64 overflow-auto rounded-md bg-background p-3 font-mono text-caption whitespace-pre">
                          {evidence}
                        </pre>
                      </div>
                    )}
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
  );
}

function QuarantineList({
  base,
  logs,
}: {
  base: string;
  logs: {
    id: string;
    file_name: string;
    asset_id: string | null;
    quarantined_error_lines: number;
    error_details: unknown;
    assets: { hostname: string } | null;
  }[];
}) {
  if (logs.length === 0) {
    return (
      <EmptyState
        icon={ClipboardCheck}
        title="수동 검토가 필요한 자산이 없습니다"
        description="모든 결과 파일이 표준 형식으로 분석되었습니다."
      />
    );
  }
  return (
    <section aria-labelledby="quarantine-title" className="flex flex-col gap-3">
      <h2 id="quarantine-title" className="flex items-start gap-2 text-body">
        <TriangleAlert
          aria-hidden="true"
          className="mt-0.5 size-4 shrink-0 text-status-warning"
        />
        형식이 표준과 다른 부분이 있어 격리된 결과 파일입니다. 판정할 수 있었던
        항목은 저장되었으니, 아래 내용을 확인한 뒤 필요하면 원본을 다시 수집해
        업로드하세요.
      </h2>
      <ul className="flex flex-col gap-3">
        {logs.map((log) => {
          const errors = errorsOf(log.error_details);
          return (
            <li
              key={log.id}
              className="flex flex-col gap-2 rounded-md border border-status-warning p-3"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="font-medium">
                    {log.assets?.hostname ?? "호스트 식별 불가"}
                  </p>
                  <p className="break-all text-caption text-muted-foreground">
                    {log.file_name} · 격리된 문제 {log.quarantined_error_lines}
                    건
                  </p>
                </div>
                {log.asset_id && (
                  <Link
                    href={`${base}?tab=items&asset=${log.asset_id}`}
                    className={buttonStyles.secondary}
                  >
                    판정된 항목 보기
                  </Link>
                )}
              </div>
              <ul className="flex flex-col gap-1 text-body">
                {errors.slice(0, 20).map((error, index) => (
                  <li key={index} className="break-all">
                    <span className="text-muted-foreground">
                      {error.line > 0 ? `${error.line}번째 줄 · ` : ""}
                    </span>
                    {error.reason}
                    {error.snippet && (
                      <code className="ml-1 font-mono text-caption text-muted-foreground">
                        {error.snippet}
                      </code>
                    )}
                  </li>
                ))}
                {errors.length > 20 && (
                  <li className="text-muted-foreground">
                    외 {errors.length - 20}건
                  </li>
                )}
              </ul>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

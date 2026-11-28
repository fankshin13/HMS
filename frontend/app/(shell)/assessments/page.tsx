import { ClipboardList, Plus } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { z } from "zod";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";
import { Forbidden } from "@/components/common/forbidden";
import { PageHeader } from "@/components/common/page-header";
import { RUN_STATUS_LABELS, isInProgress } from "@/lib/assessments/labels";
import { getMembershipWithRole } from "@/lib/auth/require-role";
import { formatSeoulDateTime } from "@/lib/format";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = { title: "진단 차수" };

const PAGE_SIZE = 20;
const pageSchema = z.coerce.number().int().min(1).catch(1);

const STATUS_TONES: Record<string, string> = {
  completed: "text-status-safe",
  failed: "text-status-danger",
};

export default async function AssessmentsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const membership = await getMembershipWithRole([
    "owner",
    "operator",
    "viewer",
  ]);
  if (!membership)
    return (
      <Forbidden description="워크스페이스 구성원만 진단 차수를 볼 수 있습니다." />
    );
  const raw = (await searchParams).page;
  const page = pageSchema.parse(Array.isArray(raw) ? raw[0] : raw);

  const supabase = await createClient();
  const from = (page - 1) * PAGE_SIZE;
  const {
    data: runs,
    count,
    error,
  } = await supabase
    .from("assessment_runs")
    .select(
      "id, title, status, total_assets, vulnerable_items_count, created_at, completed_at",
      {
        count: "exact",
      },
    )
    .eq("tenant_id", membership.tenantId)
    .order("created_at", { ascending: false })
    .range(from, from + PAGE_SIZE - 1);
  if (error) {
    console.error("진단 차수 목록 조회 실패", error.code);
    throw new Error("진단 차수 목록을 불러오지 못했습니다");
  }

  const canUpload = membership.role !== "viewer";
  const newAssessment = canUpload ? (
    <Link href="/assessments/new" className={buttonStyles.primary}>
      <Plus aria-hidden="true" className="size-4" />새 진단 차수 등록
    </Link>
  ) : undefined;
  const total = count ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <>
      <PageHeader
        title="진단 차수"
        description="진행 중이거나 완료된 취약점 진단 차수를 최신순으로 보여 줍니다."
        actions={newAssessment}
      />
      {runs.length === 0 ? (
        <EmptyState
          icon={ClipboardList}
          title="진행된 취약점 진단 차수가 없습니다"
          description="스크립트 결과 파일을 업로드하여 첫 진단 차수를 시작하세요."
          action={newAssessment}
        />
      ) : (
        <section aria-labelledby="runs-title" className="flex flex-col gap-3">
          <h2 id="runs-title" className="sr-only">
            진단 차수 목록
          </h2>
          <p role="status" className="text-body text-muted-foreground">
            전체 {total.toLocaleString("ko-KR")}건
          </p>
          <ul className="flex flex-col divide-y divide-border rounded-md border border-border">
            {runs.map((run) => (
              <li key={run.id}>
                <Link
                  href={`/assessments/${run.id}`}
                  className="grid min-h-11 grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 px-3 py-2 hover:bg-card sm:grid-cols-[1fr_8rem_6rem_7rem]"
                >
                  <span className="min-w-0">
                    <span className="block truncate font-medium">
                      {run.title}
                    </span>
                    <span className="block text-caption text-muted-foreground">
                      {formatSeoulDateTime(run.created_at)} 등록
                      <span className="sm:hidden">
                        {" "}
                        · 자산 {run.total_assets}대 · 취약{" "}
                        {run.vulnerable_items_count}건
                      </span>
                    </span>
                  </span>
                  <span className="hidden text-body sm:block">
                    자산 {run.total_assets}대
                  </span>
                  <span className="hidden text-body sm:block">
                    취약 {run.vulnerable_items_count.toLocaleString("ko-KR")}
                  </span>
                  <span
                    className={`text-body font-medium ${STATUS_TONES[run.status] ?? (isInProgress(run.status) ? "text-primary" : "")}`}
                  >
                    {RUN_STATUS_LABELS[run.status]}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
          {pages > 1 && (
            <nav
              aria-label="페이지"
              className="flex items-center justify-between gap-2"
            >
              {page > 1 ? (
                <Link
                  href={`/assessments?page=${page - 1}`}
                  className={buttonStyles.secondary}
                >
                  이전
                </Link>
              ) : (
                <span />
              )}
              <span className="text-body text-muted-foreground">
                {page} / {pages}
              </span>
              {page < pages ? (
                <Link
                  href={`/assessments?page=${page + 1}`}
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
      )}
    </>
  );
}

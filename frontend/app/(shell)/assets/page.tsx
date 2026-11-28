import { Server } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { ImportanceForm } from "@/components/assets/importance-form";
import { RiskBadge } from "@/components/assessment/risk-badge";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";
import { Forbidden } from "@/components/common/forbidden";
import { PageHeader } from "@/components/common/page-header";
import { riskCategory } from "@/lib/assessments/risk";
import { getMembershipWithRole } from "@/lib/auth/require-role";
import { formatSeoulDateTime } from "@/lib/format";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = { title: "자산 목록" };

/** 운영체제 표기. 버전 문자열에 이미 제품명이 있으면 반복하지 않는다. */
function osLabel(osType: string, version: string | null): string {
  const family = osType === "windows" ? "Windows" : "Linux";
  if (!version) return family;
  return version.toLowerCase().includes(family.toLowerCase())
    ? version
    : `${family} ${version}`;
}

export default async function AssetsPage() {
  const membership = await getMembershipWithRole([
    "owner",
    "operator",
    "viewer",
  ]);
  if (!membership)
    return (
      <Forbidden description="워크스페이스 구성원만 자산 목록을 볼 수 있습니다." />
    );

  const supabase = await createClient();
  const [assets, policy] = await Promise.all([
    supabase.rpc("get_asset_overview", { p_tenant_id: membership.tenantId }),
    supabase
      .from("risk_scoring_policies")
      .select("critical_threshold, warning_threshold")
      .eq("tenant_id", membership.tenantId)
      .maybeSingle(),
  ]);
  if (assets.error || policy.error) {
    console.error(
      "자산 목록 조회 실패",
      assets.error?.code ?? policy.error?.code,
    );
    throw new Error("자산 목록을 불러오지 못했습니다");
  }
  const thresholds = {
    critical: policy.data?.critical_threshold ?? 15,
    warning: policy.data?.warning_threshold ?? 8,
  };
  const canEdit = membership.role !== "viewer";

  return (
    <>
      <PageHeader
        title="자산 목록"
        description="진단 대상 서버와 자산 중요도(기밀성·무결성·가용성, 각 1~3점)를 관리합니다. 중요도를 바꾸면 위험 점수가 다시 계산됩니다."
        actions={
          <Link href="/scripts" className={buttonStyles.secondary}>
            자산 등록 방법 안내
          </Link>
        }
      />
      {assets.data.length === 0 ? (
        <EmptyState
          icon={Server}
          title="등록된 진단 대상 자산이 없습니다"
          description="진단 스크립트를 실행하고 결과 파일을 업로드하면 자산이 자동 등록됩니다."
          action={
            canEdit ? (
              <Link href="/assessments/new" className={buttonStyles.primary}>
                결과 파일 업로드하기
              </Link>
            ) : undefined
          }
        />
      ) : (
        <section aria-labelledby="assets-title" className="flex flex-col gap-3">
          <h2 id="assets-title" className="sr-only">
            자산 목록
          </h2>
          <p role="status" className="text-body text-muted-foreground">
            전체 {assets.data.length.toLocaleString("ko-KR")}대 · 최고 위험 점수
            높은 순
          </p>
          <ul className="flex flex-col divide-y divide-border rounded-md border border-border">
            {assets.data.map((asset) => {
              const score = Number(asset.max_risk_score);
              const importance =
                asset.confidentiality_score +
                asset.integrity_score +
                asset.availability_score;
              return (
                <li
                  key={asset.asset_id}
                  className="flex flex-col gap-3 px-3 py-3"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="truncate font-medium">{asset.hostname}</p>
                      <p className="text-caption text-muted-foreground">
                        {osLabel(asset.os_type, asset.os_version)} · 중요도{" "}
                        {importance}({asset.confidentiality_score}·
                        {asset.integrity_score}·{asset.availability_score})
                        {asset.last_assessed_at
                          ? ` · 최근 진단 ${formatSeoulDateTime(asset.last_assessed_at)}`
                          : " · 진단 기록 없음"}
                      </p>
                    </div>
                    <div className="flex flex-col items-start gap-1 text-body sm:items-end">
                      <RiskBadge
                        category={riskCategory(
                          score > 0 ? "vulnerable" : "good",
                          score,
                          thresholds,
                        )}
                        score={score}
                      />
                      <span className="text-caption text-muted-foreground">
                        취약 {asset.vulnerable} · 긴급 {asset.critical} / 점검{" "}
                        {asset.checks}
                      </span>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-end justify-between gap-3">
                    {canEdit ? (
                      <ImportanceForm
                        assetId={asset.asset_id}
                        hostname={asset.hostname}
                        values={{
                          confidentiality: asset.confidentiality_score,
                          integrity: asset.integrity_score,
                          availability: asset.availability_score,
                        }}
                      />
                    ) : (
                      <span />
                    )}
                    {asset.latest_run_id && (
                      <Link
                        href={`/assessments/${asset.latest_run_id}/items?asset=${asset.asset_id}`}
                        className={buttonStyles.secondary}
                      >
                        최근 진단 항목 보기
                      </Link>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        </section>
      )}
    </>
  );
}

import { ShieldX } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";
import { RiskPolicyForm } from "@/components/settings/risk-policy-form";
import { getMembershipWithRole } from "@/lib/auth/require-role";
import { createClient } from "@/lib/supabase/server";

export const metadata: Metadata = { title: "위험도 정책" };

const DESCRIPTION =
  "기밀성·무결성·가용성 가중치와 긴급·경고·주의 등급 기준 점수를 설정합니다. 저장하면 모든 진단의 위험 점수가 새 정책으로 다시 계산됩니다(이미 내려받은 보고서는 그대로).";

export default async function RiskPolicyPage() {
  const owner = await getMembershipWithRole(["owner"]);
  if (!owner) {
    return (
      <>
        <PageHeader title="위험도 산정 정책" description={DESCRIPTION} />
        <EmptyState
          icon={ShieldX}
          title="접근 권한이 없습니다"
          description="위험도 정책은 워크스페이스 소유자만 설정할 수 있습니다."
        />
      </>
    );
  }
  const supabase = await createClient();
  const { data, error } = await supabase
    .from("risk_scoring_policies")
    .select(
      "confidentiality_weight, integrity_weight, availability_weight, critical_threshold, warning_threshold",
    )
    .eq("tenant_id", owner.tenantId)
    .maybeSingle();
  if (error) {
    console.error("위험도 정책 조회 실패", error.code);
    throw new Error("위험도 정책을 불러오지 못했습니다");
  }
  return (
    <>
      <PageHeader title="위험도 산정 정책" description={DESCRIPTION} />
      {!data && (
        <p className="mb-4 text-body text-muted-foreground">
          아직 저장한 정책이 없어 기본값(가중치 1.00, 긴급 15점·경고 8점)을 사용
          중입니다.
        </p>
      )}
      <RiskPolicyForm
        values={{
          confidentialityWeight: Number(data?.confidentiality_weight ?? 1),
          integrityWeight: Number(data?.integrity_weight ?? 1),
          availabilityWeight: Number(data?.availability_weight ?? 1),
          criticalThreshold: data?.critical_threshold ?? 15,
          warningThreshold: data?.warning_threshold ?? 8,
        }}
      />
    </>
  );
}

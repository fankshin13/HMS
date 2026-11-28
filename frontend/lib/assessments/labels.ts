import type { Database } from "@/lib/database.types";

type Enums = Database["public"]["Enums"];

export const CATEGORY_LABELS: Record<Enums["compliance_category"], string> = {
  account_management: "계정 관리",
  directory_file_management: "파일·디렉터리 관리",
  service_management: "서비스 관리",
  patch_management: "패치 관리",
  log_management: "로그 관리",
};

export const RISK_LABELS: Record<Enums["compliance_risk_level"], string> = {
  high: "상",
  medium: "중",
  low: "하",
};

export const ITEM_STATUS_LABELS: Record<Enums["item_status"], string> = {
  good: "양호",
  vulnerable: "취약",
  na: "해당없음",
};

export const RUN_STATUS_LABELS: Record<Enums["assessment_status"], string> = {
  queued: "분석 대기",
  parsing: "파싱·판정 중",
  scoring: "판정 완료(위험도 산정 대기)",
  rendering: "보고서 생성 중",
  completed: "완료",
  failed: "실패",
};

export function isInProgress(status: Enums["assessment_status"]): boolean {
  return status === "queued" || status === "parsing";
}

export function progressPercentage(
  status: Enums["assessment_status"],
  totalAssets: number,
  processed: number,
): number {
  if (status === "queued") return 0;
  if (status !== "parsing") return 100;
  if (totalAssets === 0) return 0;
  return Math.min(99, Math.round((processed / totalAssets) * 100));
}

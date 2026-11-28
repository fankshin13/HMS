export type RiskCategory = "critical" | "warning" | "caution";

export const RISK_CATEGORY_LABELS: Record<RiskCategory, string> = {
  critical: "긴급",
  warning: "경고",
  caution: "주의",
};

/** 취약 항목의 위험 등급(backend risk_evaluator.risk_category 와 같은 규칙). 양호·해당없음은 등급이 없다. */
export function riskCategory(
  status: "good" | "vulnerable" | "na",
  score: number,
  thresholds: { critical: number; warning: number },
): RiskCategory | null {
  if (status !== "vulnerable") return null;
  if (score >= thresholds.critical) return "critical";
  if (score >= thresholds.warning) return "warning";
  return "caution";
}

export function formatScore(score: number): string {
  return score.toFixed(2);
}

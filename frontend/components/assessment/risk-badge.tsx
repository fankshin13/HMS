import { Info, OctagonAlert, TriangleAlert } from "lucide-react";
import {
  RISK_CATEGORY_LABELS,
  type RiskCategory,
  formatScore,
} from "@/lib/assessments/risk";

const STYLES = {
  critical: { icon: OctagonAlert, className: "text-status-danger" },
  warning: { icon: TriangleAlert, className: "text-status-warning" },
  caution: { icon: Info, className: "text-muted-foreground" },
} as const;

/** 위험 점수와 등급. 색과 함께 아이콘·글자로 구분한다. */
export function RiskBadge({
  category,
  score,
}: {
  category: RiskCategory | null;
  score: number;
}) {
  if (!category) return <span className="text-muted-foreground">—</span>;
  const { icon: Icon, className } = STYLES[category];
  return (
    <span className={`inline-flex items-center gap-1 font-medium ${className}`}>
      <Icon aria-hidden="true" className="size-4 shrink-0" />
      {RISK_CATEGORY_LABELS[category]} {formatScore(score)}
    </span>
  );
}

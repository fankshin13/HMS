import { CircleCheck, CircleMinus, CircleX } from "lucide-react";
import { ITEM_STATUS_LABELS } from "@/lib/assessments/labels";

const STYLES = {
  good: { icon: CircleCheck, className: "text-status-safe" },
  vulnerable: { icon: CircleX, className: "text-status-danger" },
  na: { icon: CircleMinus, className: "text-muted-foreground" },
} as const;

/** 판정 상태: 색과 함께 아이콘·글자로도 구분한다. */
export function ItemStatusBadge({ status }: { status: keyof typeof STYLES }) {
  const { icon: Icon, className } = STYLES[status];
  return (
    <span className={`inline-flex items-center gap-1 font-medium ${className}`}>
      <Icon aria-hidden="true" className="size-4 shrink-0" />
      {ITEM_STATUS_LABELS[status]}
    </span>
  );
}

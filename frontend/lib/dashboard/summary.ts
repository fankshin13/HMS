import { z } from "zod";

const count = z.coerce.number();

export const dashboardSchema = z.object({
  asset_count: count,
  run_count: count,
  in_progress_count: count,
  critical_threshold: count,
  warning_threshold: count,
  latest: z
    .object({
      id: z.string(),
      title: z.string(),
      created_at: z.string(),
      total_assets: count,
      checks: count,
      good: count,
      vulnerable: count,
      na: count,
      critical: count,
      warning: count,
      caution: count,
    })
    .nullable(),
  trend: z.array(
    z.object({
      id: z.string(),
      title: z.string(),
      created_at: z.string(),
      good: count,
      vulnerable: count,
    }),
  ),
  top_assets: z.array(
    z.object({
      asset_id: z.string(),
      hostname: z.string(),
      vulnerable: count,
      critical: count,
      score_sum: count,
    }),
  ),
  categories: z.array(
    z.object({
      category: z.string(),
      checks: count,
      vulnerable: count,
      good: count,
    }),
  ),
});

export type DashboardSummary = z.infer<typeof dashboardSchema>;

/** 양호율(%) = 양호 / (양호 + 취약), 해당없음 제외. 판정이 없으면 0. */
export function complianceRate(good: number, vulnerable: number): number {
  const judged = good + vulnerable;
  return judged === 0 ? 0 : Math.round((good * 1000) / judged) / 10;
}

import { z } from "zod";

export const ITEM_PAGE_SIZE = 50;

export const CATEGORY_VALUES = [
  "account_management",
  "directory_file_management",
  "service_management",
  "patch_management",
  "log_management",
  "security_management",
] as const;

export const itemFiltersSchema = z.object({
  asset: z.string().uuid().optional().catch(undefined),
  status: z.enum(["good", "vulnerable", "na"]).optional().catch(undefined),
  category: z.enum(CATEGORY_VALUES).optional().catch(undefined),
  page: z.coerce.number().int().min(1).catch(1),
});

export type ItemFilters = z.infer<typeof itemFiltersSchema>;
export type SearchParams = Promise<
  Record<string, string | string[] | undefined>
>;

export function firstParam(
  value: string | string[] | undefined,
): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export function parseItemFilters(
  raw: Record<string, string | string[] | undefined>,
): ItemFilters {
  return itemFiltersSchema.parse({
    asset: firstParam(raw.asset),
    status: firstParam(raw.status),
    category: firstParam(raw.category),
    page: firstParam(raw.page),
  });
}

/** 현재 필터를 유지한 채 쪽 번호 등만 바꾼 링크 */
export function itemsHref(
  base: string,
  filters: ItemFilters,
  extra: Record<string, string> = {},
): string {
  const params = new URLSearchParams(extra);
  if (filters.asset) params.set("asset", filters.asset);
  if (filters.status) params.set("status", filters.status);
  if (filters.category) params.set("category", filters.category);
  if (filters.page > 1 && !("page" in extra))
    params.set("page", String(filters.page));
  const query = params.toString();
  return query ? `${base}?${query}` : base;
}

/** stdout_snippet 첫 줄의 '[판정 근거] …' 와 스크립트 원문을 나눈다 */
export function splitSnippet(snippet: string | null): {
  reason: string | null;
  evidence: string;
} {
  if (!snippet) return { reason: null, evidence: "" };
  const [head, ...rest] = snippet.split("\n");
  if (head?.startsWith("[판정 근거] "))
    return { reason: head.slice(8), evidence: rest.join("\n") };
  return { reason: null, evidence: snippet };
}

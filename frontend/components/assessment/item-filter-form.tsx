import Link from "next/link";
import { buttonStyles } from "@/components/common/button-styles";
import { inputStyles, labelStyles } from "@/components/common/form-styles";
import { CATEGORY_LABELS, ITEM_STATUS_LABELS } from "@/lib/assessments/labels";
import {
  CATEGORY_VALUES,
  type ItemFilters,
} from "@/lib/assessments/item-filters";

const STATUS_VALUES = ["good", "vulnerable", "na"] as const;

/** 자산·판정·분야 필터 (GET 폼이라 자바스크립트 없이도 동작) */
export function ItemFilterForm({
  resetHref,
  filters,
  assetOptions,
  allAssetsLabel = "전체 자산",
  hidden = {},
}: {
  resetHref: string;
  filters: ItemFilters;
  assetOptions: { id: string; hostname: string }[];
  allAssetsLabel?: string;
  hidden?: Record<string, string>;
}) {
  return (
    <form
      method="get"
      className="grid gap-3 sm:grid-cols-2 lg:grid-cols-[1fr_1fr_1fr_auto] lg:items-end"
    >
      {Object.entries(hidden).map(([name, value]) => (
        <input key={name} type="hidden" name={name} value={value} />
      ))}
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
          <option value="">{allAssetsLabel}</option>
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
          {STATUS_VALUES.map((status) => (
            <option key={status} value={status}>
              {ITEM_STATUS_LABELS[status]}
            </option>
          ))}
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
          {CATEGORY_VALUES.map((category) => (
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
        <Link href={resetHref} className={buttonStyles.secondary}>
          초기화
        </Link>
      </div>
    </form>
  );
}

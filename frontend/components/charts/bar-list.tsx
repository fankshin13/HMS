"use client";

import { useState } from "react";

export type BarDatum = {
  key: string;
  label: string;
  value: number;
  detail: string;
};

/**
 * 단일 계열 가로 막대(값 크기 비교). 막대 끝에 값을 표시하고(텍스트는 글자색),
 * 가리키면 세부 내용을 보여 준다. 막대 두께 16px, 끝 4px 둥글게.
 */
export function BarList({
  title,
  data,
  unit,
}: {
  title: string;
  data: BarDatum[];
  unit: string;
}) {
  const [active, setActive] = useState<string | null>(null);
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <figure className="flex flex-col gap-2">
      <figcaption className="text-body font-medium">{title}</figcaption>
      <ul className="flex flex-col gap-2" onMouseLeave={() => setActive(null)}>
        {data.map((d) => (
          <li
            key={d.key}
            tabIndex={0}
            aria-label={`${d.label}: ${d.value}${unit}, ${d.detail}`}
            onMouseEnter={() => setActive(d.key)}
            onFocus={() => setActive(d.key)}
            onBlur={() => setActive(null)}
            className="grid min-h-11 grid-cols-[7.5rem_1fr] items-center gap-2 rounded-md outline-offset-2"
          >
            <span
              className="truncate text-caption text-muted-foreground"
              title={d.label}
            >
              {d.label}
            </span>
            <span className="flex items-center gap-2">
              <span
                className="h-4 rounded-r bg-primary transition-opacity"
                style={{
                  width: `${(d.value / max) * 85}%`,
                  minWidth: d.value > 0 ? 4 : 0,
                  opacity: active === null || active === d.key ? 1 : 0.45,
                }}
              />
              <span className="text-caption text-foreground">
                {d.value}
                {unit}
              </span>
              {active === d.key && (
                <span
                  role="status"
                  className="text-caption text-muted-foreground"
                >
                  {d.detail}
                </span>
              )}
            </span>
          </li>
        ))}
      </ul>
    </figure>
  );
}

"use client";

import { useId, useState } from "react";

export type ColumnDatum = {
  key: string;
  label: string;
  value: number;
  detail: string;
};

const HEIGHT = 160;
const TOP = 16;
const BOTTOM = 24;
const BAR = 24; // 막대 두께 상한
const RADIUS = 4;

/** 막대 위쪽만 둥근 경로(기준선 쪽은 직각) */
function columnPath(
  x: number,
  y: number,
  width: number,
  height: number,
): string {
  const r = Math.min(RADIUS, height, width / 2);
  return `M${x},${y + height}V${y + r}Q${x},${y} ${x + r},${y}H${x + width - r}Q${x + width},${y} ${x + width},${y + r}V${y + height}Z`;
}

/**
 * 단일 계열 세로 막대(0~max). 마우스·키보드로 막대를 가리키면 값을 보여 주고,
 * 같은 값을 표로도 볼 수 있다. 마지막 막대에만 값을 직접 표시한다.
 */
export function ColumnChart({
  title,
  data,
  max,
  unit,
}: {
  title: string;
  data: ColumnDatum[];
  max: number;
  unit: string;
}) {
  const [active, setActive] = useState<number | null>(null);
  const titleId = useId();
  const width = Math.max(data.length * 56, 280);
  const plot = HEIGHT - TOP - BOTTOM;
  const slot = width / Math.max(data.length, 1);
  const barWidth = Math.min(BAR, slot * 0.6);
  const y = (v: number) =>
    TOP + plot - (Math.max(0, Math.min(v, max)) / max) * plot;
  const current = active === null ? null : data[active];

  return (
    <figure className="flex flex-col gap-2">
      <figcaption id={titleId} className="text-body font-medium">
        {title}
      </figcaption>
      <div className="relative">
        <svg
          viewBox={`0 0 ${width} ${HEIGHT}`}
          className="h-40 w-full"
          role="img"
          aria-labelledby={titleId}
          preserveAspectRatio="none"
          onMouseLeave={() => setActive(null)}
        >
          {[0, 0.5, 1].map((ratio) => (
            <line
              key={ratio}
              x1={0}
              x2={width}
              y1={y(max * ratio)}
              y2={y(max * ratio)}
              stroke="var(--border)"
              strokeWidth={1}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {data.map((d, i) => {
            const x = i * slot + (slot - barWidth) / 2;
            const top = y(d.value);
            return (
              <g key={d.key}>
                <path
                  d={columnPath(x, top, barWidth, TOP + plot - top)}
                  fill="var(--primary)"
                  opacity={active === null || active === i ? 1 : 0.45}
                />
                <rect
                  x={i * slot}
                  y={0}
                  width={slot}
                  height={HEIGHT}
                  fill="transparent"
                  tabIndex={0}
                  aria-label={`${d.label}: ${d.value}${unit}, ${d.detail}`}
                  onMouseEnter={() => setActive(i)}
                  onFocus={() => setActive(i)}
                  onBlur={() => setActive(null)}
                />
              </g>
            );
          })}
        </svg>
        <div className="pointer-events-none absolute inset-x-0 top-0 flex justify-between text-caption text-muted-foreground">
          <span>
            {max}
            {unit}
          </span>
        </div>
        <div className="mt-1 flex text-caption text-muted-foreground">
          {data.map((d, i) => (
            <span
              key={d.key}
              className="min-w-0 flex-1 truncate px-0.5 text-center"
              title={d.label}
            >
              {i === data.length - 1 ? (
                <strong className="text-foreground">
                  {d.value}
                  {unit}
                </strong>
              ) : (
                d.label
              )}
            </span>
          ))}
        </div>
        {current && (
          <div
            role="status"
            className="absolute top-2 left-1/2 -translate-x-1/2 rounded-md border border-border bg-background px-2 py-1 text-caption shadow"
          >
            <strong>{current.label}</strong> · {current.value}
            {unit} · {current.detail}
          </div>
        )}
      </div>
      <details className="text-caption">
        <summary className="inline-flex min-h-11 cursor-pointer items-center text-muted-foreground">
          표로 보기
        </summary>
        <table className="mt-1 w-full text-left">
          <thead>
            <tr className="text-muted-foreground">
              <th className="py-1 font-normal">항목</th>
              <th className="py-1 font-normal">값</th>
              <th className="py-1 font-normal">세부</th>
            </tr>
          </thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.key} className="border-t border-border">
                <td className="py-1">{d.label}</td>
                <td className="py-1">
                  {d.value}
                  {unit}
                </td>
                <td className="py-1">{d.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}

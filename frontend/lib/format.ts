const seoulDateTime = new Intl.DateTimeFormat("ko-KR", {
  timeZone: "Asia/Seoul",
  dateStyle: "medium",
  timeStyle: "short",
});

/** timestamptz 문자열을 Asia/Seoul 기준 표시 문자열로 바꾼다. */
export function formatSeoulDateTime(value: string): string {
  return seoulDateTime.format(new Date(value));
}

export const ROLE_LABELS = {
  owner: "소유자",
  operator: "작업자",
  viewer: "열람자",
} as const;
export const STATUS_LABELS = {
  active: "활성",
  invited: "초대됨",
  suspended: "정지",
} as const;

/** 바이트 수를 KB/MB 단위로 표시한다. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Asia/Seoul 기준 오늘 날짜 (YYYY-MM-DD) */
export function seoulToday(now = new Date()): string {
  return new Intl.DateTimeFormat("sv-SE", { timeZone: "Asia/Seoul" }).format(
    now,
  );
}

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

import { z } from "zod";

export const REPORT_TYPES = ["detailed", "summary", "risk_plan"] as const;
export type ReportType = (typeof REPORT_TYPES)[number];
export const REPORT_FORMATS = ["docx", "pdf"] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export const REPORT_TITLES: Record<ReportType, string> = {
  detailed: "취약점 진단 상세 결과 보고서",
  summary: "취약점 진단 결과 보고서",
  risk_plan: "위험평가 결과 및 조치계획서",
};

export const REPORT_DESCRIPTIONS: Record<ReportType, string> = {
  detailed:
    "자산별 전수 점검 결과, 판정 근거와 스크립트 원문(줄 번호), KISA 판단 기준과 조치 방법",
  summary:
    "경영진·관리자용 요약: 판정 비율, 분야별 취약 분포 차트, 고위험 자산 순위, 종합 의견",
  risk_plan:
    "위험 매트릭스, 자산별 위험도, 긴급·경고·주의 조치 일정표, 수동 판정 변경 감사 부록",
};

export const CONTENT_TYPES: Record<ReportFormat, string> = {
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  pdf: "application/pdf",
};

const STEP_LABELS: Record<string, string> = {
  queued: "조판 대기열에서 순서를 기다리고 있습니다",
  loading: "진단 결과와 판정 변경 이력을 불러오는 중입니다",
  rendering: "3종 보고서를 조판하는 중입니다",
  detailed: "상세 결과 보고서 조판을 마쳤습니다",
  summary: "결과 보고서 차트와 요약을 만들었습니다",
  risk_plan: "위험 매트릭스와 조치계획서를 만들었습니다",
  uploading: "완성된 파일을 보안 저장소에 저장하는 중입니다",
  saving: "다운로드를 준비하는 중입니다",
  completed: "3종 보고서 조판이 끝났습니다",
  failed: "보고서 조판에 실패했습니다",
};

export function stepLabel(step: string): string {
  return STEP_LABELS[step] ?? "보고서를 조판하는 중입니다";
}

export const reportTypeSchema = z.enum(REPORT_TYPES);
export const reportFormatSchema = z.enum(REPORT_FORMATS);

const fileSchema = z.object({
  report_id: z.string(),
  file_size_bytes: z.number(),
  download_url: z.string(),
});

export const reportStatusSchema = z.object({
  assessment_run_id: z.string(),
  status: z.enum(["none", "queued", "rendering", "completed", "failed"]),
  progress_percentage: z.number(),
  current_step: z.string(),
  error_message: z.string().nullable(),
  zero_retention_active: z.boolean(),
  raw_logs_purged: z.boolean(),
  raw_logs_purged_at: z.string().nullable(),
  expires_at: z.string().nullable(),
  reports: z.array(
    z.object({
      report_type: reportTypeSchema,
      title: z.string(),
      docx: fileSchema.nullable(),
      pdf: fileSchema.nullable(),
    }),
  ),
  bundle_download_url: z.string().nullable(),
});

export type ReportStatus = z.infer<typeof reportStatusSchema>;

/** 다운로드 파일명에 쓸 수 없는 문자를 바꾼다. */
export function safeFileName(value: string): string {
  return (
    value
      .replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_")
      .replace(/\s+/g, "_")
      .slice(0, 80) || "진단"
  );
}

/** RFC 5987: 한글 파일명을 지원하는 Content-Disposition (ASCII 대체 이름 포함) */
export function contentDisposition(fileName: string): string {
  const ascii = fileName.replace(/[^\x20-\x7e]/g, "_").replace(/"/g, "_");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(fileName)}`;
}

export function reportFileName(
  type: ReportType,
  runTitle: string,
  yyyymmdd: string,
  format: ReportFormat,
): string {
  return `${safeFileName(REPORT_TITLES[type])}_${safeFileName(runTitle)}_${yyyymmdd}.${format}`;
}

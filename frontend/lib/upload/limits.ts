export const UPLOAD_LIMITS = {
  /** 업로드 파일 최대 크기 */
  maxUploadBytes: 50 * 1024 * 1024,
  /** 압축 해제 총량 상한 (압축 폭탄 방지) */
  maxExtractedBytes: 200 * 1024 * 1024,
  /** 압축 파일 안의 로그 파일 수 상한 */
  maxEntries: 500,
} as const;

export const ACCEPTED_EXTENSIONS = [".zip", ".txt", ".log"] as const;

export type UploadErrorCode =
  | "too_large"
  | "unsupported_type"
  | "zip_too_large"
  | "too_many_files"
  | "no_logs"
  | "bad_zip";

export const UPLOAD_ERROR_MESSAGES: Record<UploadErrorCode, string> = {
  too_large: "파일 크기는 최대 50MB까지 지원됩니다.",
  unsupported_type: ".zip, .txt, .log 형식의 파일만 업로드할 수 있습니다.",
  zip_too_large:
    "압축을 풀었을 때 200MB를 넘는 파일은 처리할 수 없습니다. 파일을 나누어 업로드해 주세요.",
  too_many_files:
    "압축 파일 안의 로그 파일은 최대 500개까지 처리할 수 있습니다.",
  no_logs: "압축 파일 안에 .txt 또는 .log 결과 파일이 없습니다.",
  bad_zip:
    "압축 파일을 열 수 없습니다. 파일이 손상되지 않았는지 확인해 주세요.",
};

export class UploadError extends Error {
  constructor(readonly code: UploadErrorCode) {
    super(UPLOAD_ERROR_MESSAGES[code]);
    this.name = "UploadError";
  }
}

export function extensionOf(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot === -1 ? "" : name.slice(dot).toLowerCase();
}

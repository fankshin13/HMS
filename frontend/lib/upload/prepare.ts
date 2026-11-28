import {
  type LogFile,
  extractLogFiles,
  packLogFiles,
  sha256Hex,
} from "./archive";
import { type ParsedLog, parseLog } from "./log-header";
import { type MaskingConfig, MaskingSession } from "./masking";

export interface PreparedLog extends ParsedLog {
  fileName: string;
  sizeBytes: number;
}

export interface PreparedUpload {
  payloadName: string;
  payload: Uint8Array;
  payloadSha256: string;
  logs: PreparedLog[];
  maskedIpCount: number;
  maskedUserCount: number;
  examples: { original: string; masked: string }[];
}

/** 브라우저에서: 압축 해제 → (선택) 마스킹 → 머리말 검사 → 전송용 재압축 */
export async function prepareUpload(
  fileName: string,
  bytes: Uint8Array,
  masking: MaskingConfig,
): Promise<PreparedUpload> {
  const session = new MaskingSession(masking);
  let maskedIpCount = 0;
  let maskedUserCount = 0;

  const files: LogFile[] = extractLogFiles(fileName, bytes).map((file) => {
    const result = session.mask(file.text);
    maskedIpCount += result.maskedIpCount;
    maskedUserCount += result.maskedUserCount;
    return { ...file, text: result.processedText };
  });

  const packed = packLogFiles(files, fileName);
  return {
    payloadName: packed.name,
    payload: packed.bytes,
    payloadSha256: await sha256Hex(packed.bytes),
    logs: files.map((file) => ({
      fileName: file.name,
      sizeBytes: file.sizeBytes,
      ...parseLog(file.text),
    })),
    maskedIpCount,
    maskedUserCount,
    examples: session.examples(),
  };
}

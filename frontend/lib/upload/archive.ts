import { strToU8, unzipSync, zipSync } from "fflate";
import { UPLOAD_LIMITS, UploadError, extensionOf } from "./limits";

export interface LogFile {
  /** 압축 파일 안의 경로를 뺀 파일 이름 */
  name: string;
  text: string;
  sizeBytes: number;
}

const LOG_EXTENSIONS = new Set([".txt", ".log"]);
const decoder = new TextDecoder("utf-8");
const FIXED_MTIME = new Date("1980-01-01T00:00:00Z");

function baseName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).at(-1) ?? path;
}

/** 업로드 파일(.txt/.log 또는 .zip)에서 로그 텍스트 파일 목록을 꺼낸다. 압축 폭탄·과다 항목을 막는다. */
export function extractLogFiles(
  fileName: string,
  bytes: Uint8Array,
): LogFile[] {
  if (bytes.byteLength > UPLOAD_LIMITS.maxUploadBytes)
    throw new UploadError("too_large");
  const ext = extensionOf(fileName);

  if (LOG_EXTENSIONS.has(ext)) {
    return [
      {
        name: baseName(fileName),
        text: decoder.decode(bytes),
        sizeBytes: bytes.byteLength,
      },
    ];
  }
  if (ext !== ".zip") throw new UploadError("unsupported_type");

  let declaredTotal = 0;
  let entries = 0;
  let unzipped: Record<string, Uint8Array>;
  try {
    unzipped = unzipSync(bytes, {
      filter: (file) => {
        const name = baseName(file.name);
        if (
          file.name.endsWith("/") ||
          file.name.includes("__MACOSX") ||
          name.startsWith(".")
        )
          return false;
        if (!LOG_EXTENSIONS.has(extensionOf(name))) return false;
        entries += 1;
        declaredTotal += file.originalSize;
        if (entries > UPLOAD_LIMITS.maxEntries)
          throw new UploadError("too_many_files");
        if (declaredTotal > UPLOAD_LIMITS.maxExtractedBytes)
          throw new UploadError("zip_too_large");
        return true;
      },
    });
  } catch (error) {
    if (error instanceof UploadError) throw error;
    throw new UploadError("bad_zip");
  }

  // 머리말의 크기 정보를 속이는 압축 폭탄에 대비해 실제 해제 크기도 다시 확인한다
  let actualTotal = 0;
  const files: LogFile[] = [];
  const usedNames = new Set<string>();
  for (const [path, content] of Object.entries(unzipped)) {
    actualTotal += content.byteLength;
    if (actualTotal > UPLOAD_LIMITS.maxExtractedBytes)
      throw new UploadError("zip_too_large");
    let name = baseName(path);
    for (let n = 2; usedNames.has(name); n += 1)
      name = `${n}_${baseName(path)}`;
    usedNames.add(name);
    files.push({
      name,
      text: decoder.decode(content),
      sizeBytes: content.byteLength,
    });
  }
  if (files.length === 0) throw new UploadError("no_logs");
  return files;
}

/** 마스킹한 로그 파일들을 전송용 파일 하나로 만든다(여러 개면 zip). */
export function packLogFiles(
  files: LogFile[],
  originalName: string,
): { name: string; bytes: Uint8Array } {
  const [only] = files;
  if (files.length === 1 && only && extensionOf(originalName) !== ".zip") {
    return { name: only.name, bytes: strToU8(only.text) };
  }
  const entries = Object.fromEntries(
    files.map((file) => [file.name, strToU8(file.text)]),
  );
  const zipName =
    extensionOf(originalName) === ".zip" ? baseName(originalName) : "logs.zip";
  // 같은 내용이면 같은 체크섬이 나오도록 파일 시각을 고정한다(중복 업로드 감지에 필요)
  return {
    name: zipName,
    bytes: zipSync(entries, { level: 1, mtime: FIXED_MTIME }),
  };
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // 복사본은 항상 ArrayBuffer 기반이라 WebCrypto 타입 요구사항을 만족한다
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(bytes));
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

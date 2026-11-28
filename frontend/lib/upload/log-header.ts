/** 표준 점검 스크립트 결과의 머리말을 읽어 호스트를 식별하고, 형식이 깨진 파일을 격리 대상으로 표시한다. */

export type LogProblem =
  | "missing_header"
  | "invalid_hostname"
  | "truncated"
  | "unbalanced_sections"
  | "not_text";

export interface ParsedLog {
  parseStatus: "success" | "partial_error";
  hostname: string | null;
  osType: "linux" | "windows" | null;
  osVersion: string | null;
  detectedIp: string | null;
  quarantinedErrorLines: number;
  problem: LogProblem | null;
  /** 문제가 시작된 줄 번호(1부터) */
  problemLine: number | null;
}

export const LOG_PROBLEM_MESSAGES: Record<LogProblem, string> = {
  missing_header: "표준 스크립트의 시작 표시([START])를 찾지 못했습니다.",
  invalid_hostname: "호스트명을 읽을 수 없습니다.",
  truncated: "결과 파일이 끝까지 저장되지 않았습니다([END] 없음).",
  unbalanced_sections: "점검 항목 구분 표시가 짝이 맞지 않습니다.",
  not_text: "텍스트 파일이 아닙니다.",
};

const HEADER_SCAN_LINES = 100;
const START = /^\[START\] OS=(Linux|Windows) HOSTNAME=(\S*)/;
const HOSTNAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/;
const SECTION = /^==== (\S+) (BEGIN|END) ====$/;

export function parseLog(text: string): ParsedLog {
  const lines = text.split(/\r?\n/);
  const result: ParsedLog = {
    parseStatus: "success",
    hostname: null,
    osType: null,
    osVersion: null,
    detectedIp: null,
    quarantinedErrorLines: 0,
    problem: null,
    problemLine: null,
  };
  const fail = (
    problem: LogProblem,
    line: number | null,
    errorLines = 1,
  ): ParsedLog => ({
    ...result,
    parseStatus: "partial_error",
    problem,
    problemLine: line,
    quarantinedErrorLines: errorLines,
  });

  if (text.includes("\u0000")) return fail("not_text", null);

  const headerIndex = lines
    .slice(0, HEADER_SCAN_LINES)
    .findIndex((line) => START.test(line));
  if (headerIndex === -1) return fail("missing_header", 1);
  const header = START.exec(lines[headerIndex] ?? "");
  const hostname = header?.[2] ?? "";
  if (!HOSTNAME.test(hostname))
    return fail("invalid_hostname", headerIndex + 1);

  result.hostname = hostname;
  result.osType = header?.[1] === "Windows" ? "windows" : "linux";

  for (const line of lines.slice(
    headerIndex + 1,
    headerIndex + HEADER_SCAN_LINES,
  )) {
    if (!result.osVersion && line.startsWith("[INFO] DISTRO="))
      result.osVersion = line.slice(14).trim() || null;
    if (!result.detectedIp && line.startsWith("[INFO] IP="))
      result.detectedIp = line.slice(10).trim() || null;
  }

  const open: { name: string; line: number }[] = [];
  let firstBad: number | null = null;
  let badCount = 0;
  lines.forEach((line, index) => {
    const section = SECTION.exec(line.trim());
    if (!section) return;
    const [, name, kind] = section;
    if (kind === "BEGIN") {
      open.push({ name: name ?? "", line: index + 1 });
    } else if (open.at(-1)?.name === name) {
      open.pop();
    } else {
      badCount += 1;
      firstBad ??= index + 1;
    }
  });
  if (open.length > 0) {
    badCount += open.length;
    firstBad ??= open[0]?.line ?? null;
  }

  const hasEnd = lines.some((line) => line.trim() === "[END]");
  if (!hasEnd) return fail("truncated", lines.length, Math.max(badCount, 1));
  if (badCount > 0) return fail("unbalanced_sections", firstBad, badCount);
  return result;
}

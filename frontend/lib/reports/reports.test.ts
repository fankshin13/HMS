import { describe, expect, it } from "vitest";
import {
  contentDisposition,
  reportFileName,
  safeFileName,
  stepLabel,
} from "./reports";

describe("report file names", () => {
  it("builds a Korean file name and strips unsafe characters", () => {
    expect(
      reportFileName("risk_plan", "2026/하반기: 정기", "20261128", "pdf"),
    ).toBe("위험평가_결과_및_조치계획서_2026_하반기__정기_20261128.pdf");
    expect(safeFileName('a"b<c>|d')).toBe("a_b_c__d");
    expect(safeFileName("")).toBe("진단");
  });

  it("encodes Content-Disposition per RFC 5987 with an ASCII fallback", () => {
    const header = contentDisposition("보고서 1.pdf");
    expect(header).toBe(
      `attachment; filename="___ 1.pdf"; filename*=UTF-8''%EB%B3%B4%EA%B3%A0%EC%84%9C%201.pdf`,
    );
  });

  it("labels known steps and falls back for unknown ones", () => {
    expect(stepLabel("uploading")).toContain("저장");
    expect(stepLabel("mystery")).toBe("보고서를 조판하는 중입니다");
  });
});

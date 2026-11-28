import { describe, expect, it } from "vitest";
import { parseLog } from "./log-header";
import { sampleLog } from "./test-fixtures";

describe("parseLog", () => {
  it("identifies host, OS, version and IP from a standard Linux result", () => {
    expect(parseLog(sampleLog())).toMatchObject({
      parseStatus: "success",
      hostname: "web-01",
      osType: "linux",
      osVersion: "Ubuntu 24.04.5 LTS",
      detectedIp: "192.168.1.50/24",
      problem: null,
    });
  });

  it("identifies Windows results", () => {
    expect(
      parseLog(sampleLog({ os: "Windows", hostname: "WIN-SRV-01" })),
    ).toMatchObject({
      parseStatus: "success",
      hostname: "WIN-SRV-01",
      osType: "windows",
    });
  });

  it("quarantines files without the standard header", () => {
    expect(parseLog("random text\nnot a result")).toMatchObject({
      parseStatus: "partial_error",
      hostname: null,
      problem: "missing_header",
    });
  });

  it("quarantines invalid hostnames", () => {
    expect(parseLog(sampleLog({ hostname: "../../etc" }))).toMatchObject({
      parseStatus: "partial_error",
      problem: "invalid_hostname",
    });
  });

  it("flags truncated files but keeps the host so the asset is still identified", () => {
    expect(parseLog(sampleLog({ end: false }))).toMatchObject({
      parseStatus: "partial_error",
      hostname: "web-01",
      problem: "truncated",
    });
  });

  it("flags unbalanced section markers with the first bad line", () => {
    const result = parseLog(sampleLog({ extra: "==== U-05 BEGIN ====" }));
    expect(result).toMatchObject({
      parseStatus: "partial_error",
      problem: "unbalanced_sections",
    });
    expect(result.problemLine).toBe(14);
  });

  it("rejects binary content", () => {
    expect(parseLog("PK\u0003\u0004\u0000\u0000").problem).toBe("not_text");
  });
});

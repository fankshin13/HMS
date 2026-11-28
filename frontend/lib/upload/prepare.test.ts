import { strToU8, zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { extractLogFiles } from "./archive";
import { PRIVATE_IP_REGEX } from "./masking";
import { prepareUpload } from "./prepare";
import { sampleLog } from "./test-fixtures";

const MASK_ALL = { maskIp: true, maskUsernames: true };

describe("prepareUpload", () => {
  it("sends a payload with no private IPs or custom account names when masking is on", async () => {
    const original = zipSync({
      "web-01.txt": strToU8(sampleLog()),
      "db-01.txt": strToU8(sampleLog({ hostname: "db-01", ip: "10.1.2.3" })),
    });
    const prepared = await prepareUpload("results.zip", original, MASK_ALL);

    const sent = extractLogFiles(prepared.payloadName, prepared.payload)
      .map((f) => f.text)
      .join("\n");
    expect(sent.match(PRIVATE_IP_REGEX)).toBeNull();
    expect(sent).not.toContain("hong.gildong");
    expect(
      prepared.logs.map((l) => [l.hostname, l.parseStatus, l.detectedIp]),
    ).toEqual([
      ["web-01", "success", "MASKED_IP_001/24"],
      ["db-01", "success", "MASKED_IP_004/24"], // web-01 에서 001~003 사용,
    ]);
    expect(prepared.payloadSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic so a repeated upload has the same checksum", async () => {
    const bytes = strToU8(sampleLog());
    const a = await prepareUpload("web-01.txt", bytes, MASK_ALL);
    const b = await prepareUpload("web-01.txt", bytes, MASK_ALL);
    expect(a.payloadSha256).toBe(b.payloadSha256);
  });

  it("produces the same checksum for the same zip uploaded twice", async () => {
    const zip = zipSync({
      "a.txt": strToU8(sampleLog()),
      "b.txt": strToU8(sampleLog({ hostname: "b" })),
    });
    const first = await prepareUpload("r.zip", zip, MASK_ALL);
    await new Promise((resolve) => setTimeout(resolve, 2100)); // zip 시각 해상도(2초)를 넘겨도 같아야 한다
    const second = await prepareUpload("r.zip", zip, MASK_ALL);
    expect(second.payloadSha256).toBe(first.payloadSha256);
  });

  it("keeps processing healthy hosts when one file is broken", async () => {
    const prepared = await prepareUpload(
      "mixed.zip",
      zipSync({
        "ok.txt": strToU8(sampleLog()),
        "broken.txt": strToU8("garbage"),
      }),
      MASK_ALL,
    );
    expect(prepared.logs.map((l) => l.parseStatus)).toEqual([
      "success",
      "partial_error",
    ]);
  });

  it("prepares a ~50MB zip of 50 hosts within 5 seconds", async () => {
    const padding = "x".repeat(200) + " 192.168.10.20 ACCOUNT=svc_backup\n";
    const body = padding.repeat(
      Math.ceil((0.95 * 1024 * 1024) / padding.length),
    );
    const entries = Object.fromEntries(
      Array.from({ length: 50 }, (_, i) => [
        `host-${i}.txt`,
        strToU8(sampleLog({ hostname: `host-${i}`, extra: body })),
      ]),
    );
    const zip = zipSync(entries, { level: 0 }); // 비압축 → 실제 50MB 근처
    expect(zip.byteLength).toBeGreaterThan(45 * 1024 * 1024);
    expect(zip.byteLength).toBeLessThanOrEqual(50 * 1024 * 1024);

    const started = performance.now();
    const prepared = await prepareUpload("hosts.zip", zip, MASK_ALL);
    const elapsed = performance.now() - started;

    expect(prepared.logs).toHaveLength(50);
    expect(prepared.logs.every((l) => l.parseStatus === "success")).toBe(true);
    expect(elapsed).toBeLessThan(5000);
  }, 20_000);
});

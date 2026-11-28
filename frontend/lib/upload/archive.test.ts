import { strToU8, zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { extractLogFiles, packLogFiles } from "./archive";
import { UPLOAD_LIMITS, UploadError } from "./limits";
import { sampleLog } from "./test-fixtures";

function zip(entries: Record<string, string | Uint8Array>): Uint8Array {
  return zipSync(
    Object.fromEntries(
      Object.entries(entries).map(([name, value]) => [
        name,
        typeof value === "string" ? strToU8(value) : value,
      ]),
    ),
  );
}

function codeOf(fn: () => unknown): string | null {
  try {
    fn();
    return null;
  } catch (error) {
    return error instanceof UploadError ? error.code : "other";
  }
}

describe("extractLogFiles", () => {
  it("reads a single text log", () => {
    const files = extractLogFiles("web-01.log", strToU8(sampleLog()));
    expect(files.map((f) => f.name)).toEqual(["web-01.log"]);
  });

  it("reads only .txt/.log entries from a zip, flattening folders and ignoring junk", () => {
    const files = extractLogFiles(
      "results.zip",
      zip({
        "a/web-01.txt": sampleLog(),
        "b/web-01.txt": sampleLog({ hostname: "web-02" }),
        "readme.pdf": "x",
        "__MACOSX/._web-01.txt": "x",
        ".hidden.txt": "x",
      }),
    );
    expect(files.map((f) => f.name)).toEqual(["web-01.txt", "2_web-01.txt"]);
  });

  it("rejects unsupported extensions, oversized uploads and broken zips", () => {
    expect(codeOf(() => extractLogFiles("x.exe", new Uint8Array(1)))).toBe(
      "unsupported_type",
    );
    expect(
      codeOf(() =>
        extractLogFiles(
          "x.txt",
          new Uint8Array(UPLOAD_LIMITS.maxUploadBytes + 1),
        ),
      ),
    ).toBe("too_large");
    expect(codeOf(() => extractLogFiles("x.zip", strToU8("not a zip")))).toBe(
      "bad_zip",
    );
    expect(codeOf(() => extractLogFiles("x.zip", zip({ "a.pdf": "x" })))).toBe(
      "no_logs",
    );
  });

  it("stops zip bombs above the extraction limit", () => {
    // 압축률이 높은 0 바이트 210MB → 압축 후 수백 KB
    const bomb = zip({
      "bomb.txt": new Uint8Array(
        UPLOAD_LIMITS.maxExtractedBytes + 10 * 1024 * 1024,
      ),
    });
    expect(bomb.byteLength).toBeLessThan(UPLOAD_LIMITS.maxUploadBytes);
    expect(codeOf(() => extractLogFiles("bomb.zip", bomb))).toBe(
      "zip_too_large",
    );
  });

  it("limits the number of log files", () => {
    const many = Object.fromEntries(
      Array.from({ length: UPLOAD_LIMITS.maxEntries + 1 }, (_, i) => [
        `h${i}.txt`,
        "x",
      ]),
    );
    expect(codeOf(() => extractLogFiles("many.zip", zip(many)))).toBe(
      "too_many_files",
    );
  });
});

describe("packLogFiles", () => {
  it("keeps a single text upload as text and zips multiple files", () => {
    const one = packLogFiles(
      [{ name: "a.txt", text: "hello", sizeBytes: 5 }],
      "a.txt",
    );
    expect(one.name).toBe("a.txt");
    const many = packLogFiles(
      [
        { name: "a.txt", text: "a", sizeBytes: 1 },
        { name: "b.txt", text: "b", sizeBytes: 1 },
      ],
      "results.zip",
    );
    expect(many.name).toBe("results.zip");
    expect(extractLogFiles(many.name, many.bytes).map((f) => f.text)).toEqual([
      "a",
      "b",
    ]);
  });
});

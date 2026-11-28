import { describe, expect, it } from "vitest";
import { safeNextPath } from "./redirect";

describe("safeNextPath", () => {
  it("keeps same-site relative paths", () => {
    expect(safeNextPath("/assessments/abc")).toBe("/assessments/abc");
  });

  it.each([
    null,
    undefined,
    "",
    "https://evil.example",
    "//evil.example",
    "/\\evil.example",
    "dashboard",
  ])("falls back to the dashboard for %s", (value) => {
    expect(safeNextPath(value)).toBe("/dashboard");
  });
});

import { describe, expect, it } from "vitest";
import { isInProgress, progressPercentage } from "./labels";

describe("progressPercentage", () => {
  it("is 0 while queued and 100 once parsing is finished", () => {
    expect(progressPercentage("queued", 50, 0)).toBe(0);
    expect(progressPercentage("completed", 50, 50)).toBe(100);
    expect(progressPercentage("scoring", 50, 50)).toBe(99);
    expect(progressPercentage("failed", 50, 10)).toBe(100);
  });

  it("tracks processed assets while parsing but never reports 100 early", () => {
    expect(progressPercentage("parsing", 50, 32)).toBe(64);
    expect(progressPercentage("parsing", 50, 50)).toBe(99);
    expect(progressPercentage("parsing", 0, 0)).toBe(0);
  });
});

describe("isInProgress", () => {
  it("polls while queued, parsing or scoring", () => {
    const statuses: Parameters<typeof isInProgress>[0][] = [
      "queued",
      "parsing",
      "scoring",
      "completed",
      "failed",
    ];
    expect(statuses.map(isInProgress)).toEqual([
      true,
      true,
      true,
      false,
      false,
    ]);
  });
});

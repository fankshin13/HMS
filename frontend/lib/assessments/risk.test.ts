import { describe, expect, it } from "vitest";
import { formatScore, riskCategory } from "./risk";

const DEFAULT = { critical: 15, warning: 8 };

describe("riskCategory", () => {
  it.each([
    [27, "critical"],
    [15, "critical"],
    [14.99, "warning"],
    [8, "warning"],
    [7.99, "caution"],
    [3, "caution"],
  ] as const)("score %s → %s", (score, category) => {
    expect(riskCategory("vulnerable", score, DEFAULT)).toBe(category);
  });

  it("has no category for good or na items", () => {
    expect(riskCategory("good", 0, DEFAULT)).toBeNull();
    expect(riskCategory("na", 27, DEFAULT)).toBeNull();
  });

  it("formats scores with two decimals", () => {
    expect(formatScore(27)).toBe("27.00");
  });
});

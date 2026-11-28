import { describe, expect, it } from "vitest";
import { complianceRate, dashboardSchema } from "./summary";

describe("complianceRate", () => {
  it("excludes N/A and rounds to one decimal", () => {
    expect(complianceRate(2, 1)).toBe(66.7);
    expect(complianceRate(0, 0)).toBe(0);
    expect(complianceRate(5, 0)).toBe(100);
  });
});

describe("dashboardSchema", () => {
  it("accepts an empty workspace", () => {
    const parsed = dashboardSchema.parse({
      asset_count: 0,
      run_count: 0,
      in_progress_count: 0,
      critical_threshold: 15,
      warning_threshold: 8,
      latest: null,
      trend: [],
      top_assets: [],
      categories: [],
    });
    expect(parsed.latest).toBeNull();
  });

  it("coerces numeric strings from PostgreSQL", () => {
    const parsed = dashboardSchema.parse({
      asset_count: 1,
      run_count: 1,
      in_progress_count: 0,
      critical_threshold: 15,
      warning_threshold: 8,
      latest: null,
      trend: [],
      top_assets: [
        {
          asset_id: "a",
          hostname: "db-01",
          vulnerable: 2,
          critical: 1,
          score_sum: "45.00",
        },
      ],
      categories: [],
    });
    expect(parsed.top_assets[0]?.score_sum).toBe(45);
  });
});

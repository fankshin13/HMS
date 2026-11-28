import { describe, expect, it } from "vitest";
import { itemsHref, parseItemFilters, splitSnippet } from "./item-filters";

describe("parseItemFilters", () => {
  it("drops invalid values instead of failing", () => {
    expect(
      parseItemFilters({
        asset: "x",
        status: "bad",
        category: "nope",
        page: "-3",
      }),
    ).toEqual({
      asset: undefined,
      status: undefined,
      category: undefined,
      page: 1,
    });
  });

  it("keeps valid values", () => {
    const asset = "123e4567-e89b-42d3-a456-426614174000";
    expect(
      parseItemFilters({
        asset,
        status: "vulnerable",
        category: "security_management",
        page: "2",
      }),
    ).toEqual({
      asset,
      status: "vulnerable",
      category: "security_management",
      page: 2,
    });
  });
});

describe("itemsHref", () => {
  it("keeps filters and overrides the page", () => {
    expect(
      itemsHref("/a/1/items", { status: "vulnerable", page: 3 }, { page: "4" }),
    ).toBe("/a/1/items?page=4&status=vulnerable");
  });
});

describe("splitSnippet", () => {
  it("separates the judgement reason from the evidence", () => {
    expect(splitSnippet("[판정 근거] 권한 640\n$ stat\nMODE=640")).toEqual({
      reason: "권한 640",
      evidence: "$ stat\nMODE=640",
    });
    expect(splitSnippet(null)).toEqual({ reason: null, evidence: "" });
  });
});

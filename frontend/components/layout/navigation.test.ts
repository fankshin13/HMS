import { describe, expect, it } from "vitest";
import { NAVIGATION, getBreadcrumbs, isActivePath } from "./navigation";

const allItems = NAVIGATION.flatMap((group) => group.items);

describe("NAVIGATION", () => {
  it("links to every top-level shell route in the master spec", () => {
    expect(allItems.map((item) => item.href).sort()).toEqual(
      [
        "/assessments",
        "/assets",
        "/dashboard",
        "/scripts",
        "/settings/risk-policy",
        "/settings/team",
      ].sort(),
    );
  });

  it("restricts settings menus to owners", () => {
    const settings = NAVIGATION.find((group) => group.label === "설정");
    expect(settings?.items.every((item) => item.roles.join() === "owner")).toBe(
      true,
    );
  });
});

describe("isActivePath", () => {
  it("matches nested assessment routes to the assessments menu", () => {
    const item = { href: "/assessments" };
    expect(isActivePath("/assessments", item)).toBe(true);
    expect(isActivePath("/assessments/new", item)).toBe(true);
    expect(isActivePath("/assessments/abc/items", item)).toBe(true);
    expect(isActivePath("/assessmentsx", item)).toBe(false);
  });

  it("matches exact items only on the exact path", () => {
    const item = { href: "/dashboard", exact: true };
    expect(isActivePath("/dashboard", item)).toBe(true);
    expect(isActivePath("/dashboard/x", item)).toBe(false);
  });
});

describe("getBreadcrumbs", () => {
  it("labels assessment detail paths and leaves the last crumb unlinked", () => {
    expect(getBreadcrumbs("/assessments/test-101/items")).toEqual([
      { label: "진단 차수", href: "/assessments" },
      { label: "진단 test-101", href: "/assessments/test-101" },
      { label: "점검 항목", href: undefined },
    ]);
  });

  it("does not link the settings segment, which has no page", () => {
    expect(getBreadcrumbs("/settings/team")).toEqual([
      { label: "설정", href: undefined },
      { label: "팀원 관리", href: undefined },
    ]);
  });

  it("treats /assessments/new as the new-assessment page, not an id", () => {
    expect(getBreadcrumbs("/assessments/new").at(-1)?.label).toBe("신규 진단");
  });
});

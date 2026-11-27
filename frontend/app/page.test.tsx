import { describe, expect, it } from "vitest";
import HomePage from "./page";

describe("HomePage skeleton", () => {
  it("renders a main element", () => {
    expect(HomePage().type).toBe("main");
  });
});

import { describe, expect, it } from "vitest";
import { INVITATION_MESSAGES, toInvitationProblem } from "./status";

describe("toInvitationProblem", () => {
  it.each([
    "invalid",
    "expired",
    "used",
    "email_mismatch",
    "link_failed",
    "accept_failed",
  ])("maps %s to a message", (status) => {
    const problem = toInvitationProblem(status);
    expect(problem).toBe(status);
    expect(problem && INVITATION_MESSAGES[problem].title).toBeTruthy();
  });

  it.each([undefined, "valid", "accepted", "toString", "__proto__"])(
    "ignores %s",
    (value) => {
      expect(toInvitationProblem(value)).toBeNull();
    },
  );
});

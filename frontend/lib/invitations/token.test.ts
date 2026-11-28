import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  INVITATION_TOKEN_PATTERN,
  generateInvitationToken,
  hashInvitationToken,
} from "./token";

describe("invitation tokens", () => {
  it("hashes token + salt with sha256 like the Python provisioning script", () => {
    // backend/tests/db/test_invitations.py::test_hash_invitation_token_matches_sha256_of_token_and_salt
    expect(hashInvitationToken("abc", "salt")).toBe(
      createHash("sha256").update("abcsalt").digest("hex"),
    );
  });

  it("generates unique 64-char hex tokens", () => {
    const a = generateInvitationToken();
    const b = generateInvitationToken();
    expect(a).toMatch(INVITATION_TOKEN_PATTERN);
    expect(a).not.toBe(b);
  });
});

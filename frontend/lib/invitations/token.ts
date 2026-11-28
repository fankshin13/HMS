import { createHash, randomBytes } from "node:crypto";

/** 32바이트 무작위 토큰(hex 64자). 원본은 링크에만 담고 DB 에는 해시만 저장한다. */
export function generateInvitationToken(): string {
  return randomBytes(32).toString("hex");
}

/** backend/scripts/provision_owner.py 의 hash_invitation_token 과 같은 규칙: sha256(token + salt) */
export function hashInvitationToken(rawToken: string, salt: string): string {
  return createHash("sha256")
    .update(rawToken + salt, "utf8")
    .digest("hex");
}

export const INVITATION_TOKEN_PATTERN = /^[0-9a-f]{64}$/;

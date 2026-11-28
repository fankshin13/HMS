export type InvitationProblem =
  | "invalid"
  | "expired"
  | "used"
  | "email_mismatch"
  | "link_failed"
  | "accept_failed";

export const INVITATION_MESSAGES: Record<
  InvitationProblem,
  { title: string; description: string }
> = {
  invalid: {
    title: "유효하지 않은 초대 링크입니다",
    description:
      "전달받은 주소를 다시 확인해 주세요. 문제가 계속되면 관리자에게 새 링크를 요청하세요.",
  },
  expired: {
    title: "초대 링크가 만료되었습니다",
    description:
      "유효기간이 지났거나 관리자가 철회한 링크입니다. 관리자에게 새 링크 발급을 요청해 주세요.",
  },
  used: {
    title: "이미 사용이 완료된 초대 링크입니다",
    description:
      "이미 참여하셨다면 아래에서 이메일로 로그인하세요. 참여한 적이 없다면 관리자에게 문의하세요.",
  },
  email_mismatch: {
    title: "초대받은 이메일과 로그인한 계정이 다릅니다",
    description:
      "초대 링크를 받은 이메일 주소로 로그인해야 워크스페이스에 참여할 수 있습니다.",
  },
  accept_failed: {
    title: "초대를 처리하지 못했습니다",
    description:
      "잠시 후 초대 링크를 다시 열어 주세요. 문제가 계속되면 관리자에게 문의하세요.",
  },
  link_failed: {
    title: "로그인 링크를 확인하지 못했습니다",
    description:
      "링크가 만료되었거나 다른 브라우저에서 열렸습니다. 초대 링크를 연 같은 브라우저에서 메일의 링크를 다시 열어 주세요.",
  },
};

function isInvitationProblem(value: string): value is InvitationProblem {
  return Object.hasOwn(INVITATION_MESSAGES, value);
}

export function toInvitationProblem(
  value: string | undefined,
): InvitationProblem | null {
  return value !== undefined && isInvitationProblem(value) ? value : null;
}

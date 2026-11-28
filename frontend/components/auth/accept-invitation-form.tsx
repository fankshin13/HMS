"use client";

import { LoaderCircle } from "lucide-react";
import { useActionState } from "react";
import {
  type AuthFormState,
  startInvitationSignIn,
} from "@/app/auth/verify/actions";
import { ErrorAlert } from "@/components/common/alert";
import { buttonStyles } from "@/components/common/button-styles";

const initialState: AuthFormState = { error: null };

export function AcceptInvitationForm({ token }: { token: string }) {
  const [state, formAction, pending] = useActionState(
    startInvitationSignIn,
    initialState,
  );

  return (
    <form action={formAction} className="flex w-full flex-col gap-3">
      <input type="hidden" name="token" value={token} />
      {state.error && <ErrorAlert>{state.error}</ErrorAlert>}
      <button type="submit" disabled={pending} className={buttonStyles.primary}>
        {pending && (
          <LoaderCircle
            aria-hidden="true"
            className="size-4 motion-safe:animate-spin"
          />
        )}
        {pending ? "로그인 메일을 보내는 중…" : "워크스페이스 참여 및 시작하기"}
      </button>
      <p className="text-caption text-muted-foreground">
        초대받은 이메일로 로그인 링크를 보냅니다. 이 브라우저에서 메일의 링크를
        열어 주세요.
      </p>
    </form>
  );
}

"use client";

import { LoaderCircle } from "lucide-react";
import { useActionState } from "react";
import { type AuthFormState, sendLoginLink } from "@/app/auth/verify/actions";
import { ErrorAlert } from "@/components/common/alert";
import { buttonStyles } from "@/components/common/button-styles";
import { inputStyles, labelStyles } from "@/components/common/form-styles";

const initialState: AuthFormState = { error: null };

export function LoginForm() {
  const [state, formAction, pending] = useActionState(
    sendLoginLink,
    initialState,
  );

  return (
    <form action={formAction} className="flex w-full flex-col gap-3 text-left">
      <label htmlFor="login-email" className={labelStyles}>
        이메일
      </label>
      <input
        id="login-email"
        name="email"
        type="email"
        required
        autoComplete="email"
        className={inputStyles}
      />
      {state.error && <ErrorAlert>{state.error}</ErrorAlert>}
      <button type="submit" disabled={pending} className={buttonStyles.primary}>
        {pending && (
          <LoaderCircle
            aria-hidden="true"
            className="size-4 motion-safe:animate-spin"
          />
        )}
        {pending ? "보내는 중…" : "로그인 링크 받기"}
      </button>
    </form>
  );
}

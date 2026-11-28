"use client";

import { LoaderCircle } from "lucide-react";
import { useActionState } from "react";
import {
  type RevokeState,
  revokeInvitation,
} from "@/app/(shell)/settings/team/actions";
import { buttonStyles } from "@/components/common/button-styles";

const initialState: RevokeState = { error: null };

export function RevokeButton({
  invitationId,
  email,
}: {
  invitationId: string;
  email: string;
}) {
  const [state, formAction, pending] = useActionState(
    revokeInvitation,
    initialState,
  );

  return (
    <form action={formAction} className="flex flex-col items-start gap-1">
      <input type="hidden" name="invitationId" value={invitationId} />
      <button
        type="submit"
        disabled={pending}
        className={buttonStyles.secondary}
        aria-label={`${email} 초대 철회`}
      >
        {pending && (
          <LoaderCircle
            aria-hidden="true"
            className="size-4 motion-safe:animate-spin"
          />
        )}
        초대 철회
      </button>
      {state.error && (
        <span role="alert" className="text-caption text-status-danger">
          {state.error}
        </span>
      )}
    </form>
  );
}

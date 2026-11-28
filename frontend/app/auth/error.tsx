"use client";

import { TriangleAlert } from "lucide-react";
import { useEffect } from "react";
import { buttonStyles } from "@/components/common/button-styles";

export default function AuthError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("인증 화면 오류", error.digest ?? error.message);
  }, [error]);

  return (
    <section
      role="alert"
      className="flex w-full max-w-sm flex-col items-center gap-4 rounded-md border border-border bg-card p-6 text-center"
    >
      <TriangleAlert
        aria-hidden="true"
        className="size-8 text-status-warning"
      />
      <h1 className="text-h2">요청을 처리하지 못했습니다</h1>
      <p className="text-body text-muted-foreground">
        잠시 후 다시 시도해 주세요.
      </p>
      <button type="button" className={buttonStyles.secondary} onClick={reset}>
        다시 시도
      </button>
    </section>
  );
}

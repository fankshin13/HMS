"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

/** 명령어·체크섬 복사 버튼. 실패하면 직접 선택해 복사하도록 안내한다. */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed"); // 권한 거부 등: 아래 안내 문구로 알린다
    }
  };

  return (
    <span className="flex shrink-0 items-center gap-2">
      <button
        type="button"
        onClick={copy}
        aria-label={`${label} 복사`}
        className="inline-flex size-11 items-center justify-center rounded-md border border-border text-muted-foreground hover:bg-border hover:text-foreground"
      >
        {state === "copied" ? (
          <Check aria-hidden="true" className="size-4" />
        ) : (
          <Copy aria-hidden="true" className="size-4" />
        )}
      </button>
      <span role="status" className="sr-only">
        {state === "copied"
          ? `${label}을(를) 복사했습니다`
          : state === "failed"
            ? "복사하지 못했습니다. 직접 선택해 복사해 주세요."
            : ""}
      </span>
    </span>
  );
}

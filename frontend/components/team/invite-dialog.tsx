"use client";

import { Check, Copy, LoaderCircle, UserPlus, X } from "lucide-react";
import { useActionState, useRef, useState } from "react";
import {
  type InviteFormState,
  createInvitation,
} from "@/app/(shell)/settings/team/actions";
import { ErrorAlert } from "@/components/common/alert";
import { buttonStyles } from "@/components/common/button-styles";
import { inputStyles, labelStyles } from "@/components/common/form-styles";
import { formatSeoulDateTime } from "@/lib/format";

const initialState: InviteFormState = { status: "idle" };

export function InviteDialog({
  label = "팀원 초대 링크 생성",
}: {
  label?: string;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const [formKey, setFormKey] = useState(0);

  const open = () => {
    setFormKey((key) => key + 1); // 열 때마다 이전 결과를 지운 새 폼
    dialogRef.current?.showModal();
  };

  return (
    <>
      <button
        type="button"
        className={buttonStyles.primary}
        onClick={open}
        aria-haspopup="dialog"
      >
        <UserPlus aria-hidden="true" className="size-4" />
        {label}
      </button>
      <dialog
        ref={dialogRef}
        aria-labelledby="invite-dialog-title"
        className="m-auto w-[calc(100%-2rem)] max-w-md rounded-md border border-border bg-card p-0 text-foreground backdrop:bg-background/80"
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-2">
          <h2 id="invite-dialog-title" className="text-h3">
            팀원 초대 링크 생성
          </h2>
          <button
            type="button"
            className="inline-flex size-11 items-center justify-center rounded-md hover:bg-border"
            aria-label="닫기"
            onClick={() => dialogRef.current?.close()}
          >
            <X aria-hidden="true" className="size-5" />
          </button>
        </div>
        <InviteForm key={formKey} />
      </dialog>
    </>
  );
}

function InviteForm() {
  const [state, formAction, pending] = useActionState(
    createInvitation,
    initialState,
  );

  if (state.status === "created") return <CreatedLink state={state} />;

  return (
    <form action={formAction} className="flex flex-col gap-3 p-4">
      <label htmlFor="invite-name" className={labelStyles}>
        이름
      </label>
      <input
        id="invite-name"
        name="name"
        required
        maxLength={100}
        className={inputStyles}
      />
      <label htmlFor="invite-email" className={labelStyles}>
        이메일
      </label>
      <input
        id="invite-email"
        name="email"
        type="email"
        required
        className={inputStyles}
      />
      <label htmlFor="invite-role" className={labelStyles}>
        역할
      </label>
      <select
        id="invite-role"
        name="role"
        defaultValue="operator"
        className={inputStyles}
      >
        <option value="operator">작업자 — 진단 업로드·판정 수정</option>
        <option value="viewer">열람자 — 결과·보고서 열람</option>
      </select>
      <label htmlFor="invite-hours" className={labelStyles}>
        유효기간(시간, 1~72)
      </label>
      <input
        id="invite-hours"
        name="validHours"
        type="number"
        min={1}
        max={72}
        defaultValue={24}
        required
        className={inputStyles}
      />
      {state.status === "error" && <ErrorAlert>{state.message}</ErrorAlert>}
      <button
        type="submit"
        disabled={pending}
        className={`${buttonStyles.primary} mt-2`}
      >
        {pending && (
          <LoaderCircle
            aria-hidden="true"
            className="size-4 motion-safe:animate-spin"
          />
        )}
        {pending ? "생성 중…" : "초대 링크 생성"}
      </button>
    </form>
  );
}

function CreatedLink({
  state,
}: {
  state: Extract<InviteFormState, { status: "created" }>;
}) {
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(state.inviteUrl);
      setCopy("copied");
    } catch {
      setCopy("failed"); // 권한 거부 등: 사용자가 직접 선택해 복사하도록 안내한다
    }
  };

  return (
    <div className="flex flex-col gap-3 p-4">
      <p className="text-body">
        <strong>{state.email}</strong> 님의 초대 링크입니다. 이 창을 닫으면 다시
        볼 수 없으니 지금 복사해 사내 메신저 등 안전한 경로로 본인에게만
        전달하세요.
      </p>
      <label htmlFor="invite-url" className={labelStyles}>
        초대 링크 (만료 {formatSeoulDateTime(state.expiresAt)})
      </label>
      <input
        id="invite-url"
        readOnly
        value={state.inviteUrl}
        className={inputStyles}
        onFocus={(event) => event.currentTarget.select()}
      />
      <button type="button" className={buttonStyles.primary} onClick={copyLink}>
        {copy === "copied" ? (
          <Check aria-hidden="true" className="size-4" />
        ) : (
          <Copy aria-hidden="true" className="size-4" />
        )}
        {copy === "copied" ? "복사됨" : "링크 복사"}
      </button>
      <p role="status" className="text-caption text-muted-foreground">
        {copy === "copied" && "클립보드에 복사했습니다."}
        {copy === "failed" &&
          "자동 복사에 실패했습니다. 위 입력란을 선택해 직접 복사해 주세요."}
      </p>
    </div>
  );
}

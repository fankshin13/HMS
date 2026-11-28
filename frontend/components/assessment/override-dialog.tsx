"use client";

import { LoaderCircle, PencilLine, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useId, useRef, useState } from "react";
import { z } from "zod";
import { ErrorAlert } from "@/components/common/alert";
import { buttonStyles } from "@/components/common/button-styles";
import { inputStyles, labelStyles } from "@/components/common/form-styles";
import { ITEM_STATUS_LABELS } from "@/lib/assessments/labels";

type Status = "good" | "vulnerable" | "na";
const STATUSES: Status[] = ["good", "vulnerable", "na"];
const MIN_REASON = 5;
const MAX_REASON = 1000;
const errorSchema = z.object({ error: z.object({ message: z.string() }) });

/** 판정 수동 변경 대화상자. 저장하면 서버가 점수 재산정·감사 기록을 하고, 화면을 새로 그린다. */
export function OverrideDialog({
  runId,
  itemId,
  itemLabel,
  autoStatus,
  finalStatus,
  onSaved,
}: {
  runId: string;
  itemId: string;
  itemLabel: string;
  autoStatus: Status;
  finalStatus: Status;
  onSaved: (message: string) => void;
}) {
  const router = useRouter();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const [status, setStatus] = useState<Status>(finalStatus);
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const trimmed = reason.trim().length;
  const canSave =
    !pending &&
    status !== finalStatus &&
    trimmed >= MIN_REASON &&
    trimmed <= MAX_REASON;

  const open = () => {
    setStatus(finalStatus === "vulnerable" ? "good" : finalStatus);
    setReason("");
    setError(null);
    dialogRef.current?.showModal();
  };

  const save = async () => {
    setPending(true);
    setError(null);
    try {
      const response = await fetch(
        `/api/assessments/${runId}/items/${itemId}/override`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ new_status: status, reason }),
        },
      );
      if (!response.ok) {
        const body = errorSchema.safeParse(await response.json());
        setError(
          body.success
            ? body.data.error.message
            : "판정을 변경하지 못했습니다. 잠시 후 다시 시도해 주세요.",
        );
        return;
      }
      dialogRef.current?.close();
      onSaved(
        `${itemLabel} 판정을 '${ITEM_STATUS_LABELS[status]}'(으)로 변경했습니다.`,
      );
      router.refresh();
    } catch {
      setError(
        "네트워크 오류로 판정을 변경하지 못했습니다. 다시 시도해 주세요.",
      );
    } finally {
      setPending(false);
    }
  };

  return (
    <>
      <button
        type="button"
        className={buttonStyles.secondary}
        onClick={open}
        aria-haspopup="dialog"
      >
        <PencilLine aria-hidden="true" className="size-4" />
        판정 변경
      </button>
      <dialog
        ref={dialogRef}
        aria-labelledby={titleId}
        className="m-auto w-[calc(100%-2rem)] max-w-lg rounded-md border border-border bg-card p-0 text-foreground backdrop:bg-background/80"
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-2">
          <h2 id={titleId} className="text-h3">
            판정 변경 · {itemLabel}
          </h2>
          <button
            type="button"
            aria-label="닫기"
            onClick={() => dialogRef.current?.close()}
            className="inline-flex size-11 items-center justify-center rounded-md hover:bg-border"
          >
            <X aria-hidden="true" className="size-5" />
          </button>
        </div>
        <form
          className="flex flex-col gap-4 p-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (canSave) void save();
          }}
        >
          <p className="text-body text-muted-foreground">
            자동 판정 {ITEM_STATUS_LABELS[autoStatus]} · 현재 판정{" "}
            {ITEM_STATUS_LABELS[finalStatus]}
          </p>
          <fieldset className="flex flex-col gap-2">
            <legend className={`${labelStyles} mb-2`}>변경할 판정</legend>
            <div className="flex flex-wrap gap-2">
              {STATUSES.map((value) => (
                <label
                  key={value}
                  className="flex min-h-11 cursor-pointer items-center gap-2 rounded-md border border-muted-foreground px-3 has-[:checked]:border-primary has-[:checked]:bg-primary/15"
                >
                  <input
                    type="radio"
                    name="new_status"
                    value={value}
                    checked={status === value}
                    onChange={() => setStatus(value)}
                    className="size-4 accent-primary-action"
                  />
                  {ITEM_STATUS_LABELS[value]}
                  {value === finalStatus && (
                    <span className="text-caption text-muted-foreground">
                      (현재)
                    </span>
                  )}
                </label>
              ))}
            </div>
          </fieldset>
          <div className="flex flex-col gap-1">
            <label htmlFor={`${titleId}-reason`} className={labelStyles}>
              변경 사유 (공백 제외 5자 이상)
            </label>
            <textarea
              id={`${titleId}-reason`}
              value={reason}
              maxLength={MAX_REASON}
              rows={4}
              onChange={(event) => setReason(event.target.value)}
              placeholder="예: 사내 보안 승인(결재번호 SEC-2026-088)에 따라 침입차단시스템에서 원격 접속을 차단 중"
              className={`${inputStyles} py-2`}
              aria-describedby={`${titleId}-count`}
            />
            <span
              id={`${titleId}-count`}
              className="text-caption text-muted-foreground"
            >
              {trimmed}/{MAX_REASON}자
              {trimmed > 0 && trimmed < MIN_REASON
                ? " · 5자 이상 입력해 주세요"
                : ""}
              {status === finalStatus
                ? " · 현재와 다른 판정을 선택해 주세요"
                : ""}
            </span>
          </div>
          {error && <ErrorAlert>{error}</ErrorAlert>}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              className={buttonStyles.secondary}
              onClick={() => dialogRef.current?.close()}
            >
              취소
            </button>
            <button
              type="submit"
              className={buttonStyles.primary}
              disabled={!canSave}
            >
              {pending && (
                <LoaderCircle
                  aria-hidden="true"
                  className="size-4 motion-safe:animate-spin"
                />
              )}
              {pending ? "저장 중…" : "저장"}
            </button>
          </div>
        </form>
      </dialog>
    </>
  );
}

"use client";

import { History, LoaderCircle, X } from "lucide-react";
import { useId, useRef, useState } from "react";
import { z } from "zod";
import { ErrorAlert } from "@/components/common/alert";
import { buttonStyles } from "@/components/common/button-styles";
import { ITEM_STATUS_LABELS } from "@/lib/assessments/labels";
import { formatSeoulDateTime } from "@/lib/format";

const auditsSchema = z.object({
  audits: z.array(
    z.object({
      audit_id: z.string(),
      actor_name: z.string().nullable(),
      actor_email: z.string().nullable(),
      previous_status: z.enum(["good", "vulnerable", "na"]),
      new_status: z.enum(["good", "vulnerable", "na"]),
      reason: z.string(),
      created_at: z.string(),
    }),
  ),
});
type Audit = z.infer<typeof auditsSchema>["audits"][number];

/** 항목의 판정 변경 이력(최신순)을 대화상자로 보여 준다 */
export function AuditTrail({
  runId,
  itemId,
  itemLabel,
}: {
  runId: string;
  itemId: string;
  itemLabel: string;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const [state, setState] = useState<"loading" | "error" | Audit[]>("loading");

  const open = async () => {
    setState("loading");
    dialogRef.current?.showModal();
    try {
      const response = await fetch(
        `/api/assessments/${runId}/items/${itemId}/audits`,
        { cache: "no-store" },
      );
      const parsed = auditsSchema.safeParse(await response.json());
      setState(response.ok && parsed.success ? parsed.data.audits : "error");
    } catch {
      setState("error");
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
        <History aria-hidden="true" className="size-4" />
        변경 이력
      </button>
      <dialog
        ref={dialogRef}
        aria-labelledby={titleId}
        className="m-auto w-[calc(100%-2rem)] max-w-lg rounded-md border border-border bg-card p-0 text-foreground backdrop:bg-background/80"
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-2">
          <h2 id={titleId} className="text-h3">
            변경 이력 · {itemLabel}
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
        <div
          className="max-h-[70dvh] overflow-y-auto p-4"
          role="status"
          aria-live="polite"
        >
          {state === "loading" && (
            <p className="flex items-center gap-2 text-body">
              <LoaderCircle
                aria-hidden="true"
                className="size-4 motion-safe:animate-spin"
              />
              변경 이력을 불러오는 중입니다…
            </p>
          )}
          {state === "error" && (
            <div className="flex flex-col items-start gap-2">
              <ErrorAlert>변경 이력을 불러오지 못했습니다.</ErrorAlert>
              <button
                type="button"
                className={buttonStyles.secondary}
                onClick={open}
              >
                다시 시도
              </button>
            </div>
          )}
          {Array.isArray(state) && state.length === 0 && (
            <p className="text-body">변경 이력이 없습니다.</p>
          )}
          {Array.isArray(state) && state.length > 0 && (
            <ol className="flex flex-col gap-3">
              {state.map((audit) => (
                <li
                  key={audit.audit_id}
                  className="flex flex-col gap-1 border-l-2 border-primary pl-3 text-body"
                >
                  <span className="font-medium">
                    {ITEM_STATUS_LABELS[audit.previous_status]} →{" "}
                    {ITEM_STATUS_LABELS[audit.new_status]}
                  </span>
                  <span className="whitespace-pre-wrap">{audit.reason}</span>
                  <span className="text-caption text-muted-foreground">
                    {formatSeoulDateTime(audit.created_at)} ·{" "}
                    {audit.actor_name ?? "알 수 없음"}
                    {audit.actor_email ? ` (${audit.actor_email})` : ""}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </dialog>
    </>
  );
}

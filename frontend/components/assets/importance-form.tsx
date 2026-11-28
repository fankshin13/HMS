"use client";

import { LoaderCircle } from "lucide-react";
import { useActionState } from "react";
import {
  type ImportanceState,
  updateImportance,
} from "@/app/(shell)/assets/actions";
import { buttonStyles } from "@/components/common/button-styles";

const initial: ImportanceState = { status: "idle", message: "" };
const FIELDS = [
  { name: "confidentiality", label: "기밀성" },
  { name: "integrity", label: "무결성" },
  { name: "availability", label: "가용성" },
] as const;

/** 자산 중요도(1~3점) 편집. 저장하면 이 자산의 위험 점수가 다시 계산된다. */
export function ImportanceForm({
  assetId,
  hostname,
  values,
}: {
  assetId: string;
  hostname: string;
  values: Record<(typeof FIELDS)[number]["name"], number>;
}) {
  const [state, action, pending] = useActionState(updateImportance, initial);
  return (
    <form
      action={action}
      className="flex flex-col gap-2"
      aria-label={`${hostname} 중요도`}
    >
      <input type="hidden" name="assetId" value={assetId} />
      <div className="flex flex-wrap items-end gap-2">
        {FIELDS.map((field) => (
          <label
            key={field.name}
            className="flex flex-col gap-1 text-caption text-muted-foreground"
          >
            {field.label}
            <select
              name={field.name}
              defaultValue={values[field.name]}
              className="min-h-11 rounded-md border border-muted-foreground bg-background px-2 text-body text-foreground"
            >
              <option value={1}>1 (낮음)</option>
              <option value={2}>2 (보통)</option>
              <option value={3}>3 (높음)</option>
            </select>
          </label>
        ))}
        <button
          type="submit"
          className={buttonStyles.secondary}
          disabled={pending}
        >
          {pending && (
            <LoaderCircle
              aria-hidden="true"
              className="size-4 motion-safe:animate-spin"
            />
          )}
          중요도 저장
        </button>
      </div>
      <p
        role="status"
        aria-live="polite"
        className={`text-caption ${state.status === "error" ? "text-status-danger" : "text-status-safe"}`}
      >
        {state.message}
      </p>
    </form>
  );
}

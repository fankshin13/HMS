"use client";

import { useState } from "react";
import { AuditTrail } from "./audit-trail";
import { OverrideDialog } from "./override-dialog";

type Status = "good" | "vulnerable" | "na";

/** 항목별 동작: 판정 변경(owner·operator) + 변경 이력. 저장 결과는 화면 낭독기에 알린다. */
export function ItemActions({
  runId,
  itemId,
  itemLabel,
  autoStatus,
  finalStatus,
  canEdit,
  hasHistory,
}: {
  runId: string;
  itemId: string;
  itemLabel: string;
  autoStatus: Status;
  finalStatus: Status;
  canEdit: boolean;
  hasHistory: boolean;
}) {
  const [message, setMessage] = useState("");
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-2">
        {canEdit && (
          <OverrideDialog
            runId={runId}
            itemId={itemId}
            itemLabel={itemLabel}
            autoStatus={autoStatus}
            finalStatus={finalStatus}
            onSaved={setMessage}
          />
        )}
        {hasHistory && (
          <AuditTrail runId={runId} itemId={itemId} itemLabel={itemLabel} />
        )}
      </div>
      <p
        role="status"
        aria-live="polite"
        className="text-caption text-status-safe"
      >
        {message}
      </p>
    </div>
  );
}

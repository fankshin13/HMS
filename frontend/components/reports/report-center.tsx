"use client";

import {
  CircleCheck,
  Download,
  FileText,
  LoaderCircle,
  RotateCcw,
  ShieldCheck,
  X,
} from "lucide-react";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { z } from "zod";
import { ErrorAlert } from "@/components/common/alert";
import { buttonStyles } from "@/components/common/button-styles";
import { formatBytes, formatSeoulDateTime } from "@/lib/format";
import {
  REPORT_DESCRIPTIONS,
  type ReportStatus,
  reportStatusSchema,
  stepLabel,
} from "@/lib/reports/reports";

const POLL_MS = 2000;
const errorSchema = z.object({ error: z.object({ message: z.string() }) });
const purgeSchema = z.object({ purged_log_count: z.number() });

async function errorMessage(response: Response, fallback: string) {
  const body = errorSchema.safeParse(await response.json().catch(() => null));
  return body.success ? body.data.error.message : fallback;
}

/** 3종 보고서 생성·진행률·다운로드. 조판 중에는 2초마다 상태를 확인한다. */
export function ReportCenter({
  runId,
  initial,
  canGenerate,
}: {
  runId: string;
  initial: ReportStatus;
  canGenerate: boolean;
}) {
  const [status, setStatus] = useState(initial);
  const [requesting, setRequesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [pollFailed, setPollFailed] = useState(false);
  const busy = status.status === "queued" || status.status === "rendering";

  const refresh = useCallback(async () => {
    const response = await fetch(`/api/assessments/${runId}/reports`, {
      cache: "no-store",
    });
    const parsed = reportStatusSchema.safeParse(await response.json());
    if (!response.ok || !parsed.success)
      throw new Error(`status ${response.status}`);
    return parsed.data;
  }, [runId]);

  useEffect(() => {
    if (!busy || pollFailed) return;
    let cancelled = false;
    const timer = window.setInterval(async () => {
      try {
        const next = await refresh();
        if (cancelled) return;
        setStatus(next);
        if (next.status === "completed") {
          setNotice(
            "3종 보고서 조판이 완료되었습니다. 지금 내려받을 수 있습니다.",
          );
        }
      } catch {
        if (!cancelled) setPollFailed(true);
      }
    }, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [busy, pollFailed, refresh]);

  const generate = async (force: boolean) => {
    setRequesting(true);
    setError(null);
    setNotice("");
    try {
      const response = await fetch(
        `/api/assessments/${runId}/reports/generate${force ? "?force=true" : ""}`,
        { method: "POST" },
      );
      if (!response.ok) {
        setError(
          await errorMessage(response, "보고서 생성을 요청하지 못했습니다."),
        );
        return;
      }
      setPollFailed(false);
      setStatus(await refresh());
    } catch {
      setError("네트워크 오류로 보고서 생성을 요청하지 못했습니다.");
    } finally {
      setRequesting(false);
    }
  };

  const purgeOnDownload =
    canGenerate && status.zero_retention_active && !status.raw_logs_purged;

  return (
    <div className="flex flex-col gap-6">
      <RetentionBadge status={status} />

      {status.status === "failed" && (
        <div className="flex flex-col items-start gap-3">
          <ErrorAlert>
            보고서 조판 중 오류가 발생했습니다:{" "}
            {status.error_message ?? "알 수 없는 오류"}
          </ErrorAlert>
          {canGenerate && (
            <button
              type="button"
              className={buttonStyles.primary}
              disabled={requesting}
              onClick={() => generate(false)}
            >
              <RotateCcw aria-hidden="true" className="size-4" />
              조판 재시도
            </button>
          )}
        </div>
      )}

      {busy && (
        <section
          aria-labelledby="render-progress"
          className="flex flex-col gap-3 rounded-md border border-border bg-card p-4"
        >
          <h2 id="render-progress" className="flex items-center gap-2 text-h3">
            <LoaderCircle
              aria-hidden="true"
              className="size-4 motion-safe:animate-spin"
            />
            3종 보고서 조판 중… {status.progress_percentage}%
          </h2>
          <progress
            max={100}
            value={status.progress_percentage}
            aria-labelledby="render-progress"
            className="h-2 w-full accent-primary-action"
          />
          <p role="status" className="text-body text-muted-foreground">
            {stepLabel(status.current_step)}
          </p>
          {pollFailed && (
            <div className="flex flex-col items-start gap-2">
              <ErrorAlert>진행 상태를 확인하지 못했습니다.</ErrorAlert>
              <button
                type="button"
                className={buttonStyles.secondary}
                onClick={() => setPollFailed(false)}
              >
                다시 확인
              </button>
            </div>
          )}
        </section>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {status.status === "completed" && status.bundle_download_url ? (
          <BundleDownload
            runId={runId}
            url={status.bundle_download_url}
            purgeOnDownload={purgeOnDownload}
            onPurged={(count) => {
              setNotice(
                `ZIP 다운로드를 마쳤고, 원본 진단 로그 ${count}개를 영구 삭제했습니다.`,
              );
              refresh().then(setStatus, () => undefined);
            }}
            onError={setError}
          />
        ) : (
          canGenerate &&
          status.status !== "failed" && (
            <button
              type="button"
              className={buttonStyles.primary}
              disabled={busy || requesting}
              onClick={() => generate(false)}
            >
              {(busy || requesting) && (
                <LoaderCircle
                  aria-hidden="true"
                  className="size-4 motion-safe:animate-spin"
                />
              )}
              {busy ? "조판 진행 중…" : "3종 보고서 일괄 생성 시작"}
            </button>
          )
        )}
        {status.status === "completed" && canGenerate && (
          <button
            type="button"
            className={buttonStyles.secondary}
            disabled={requesting}
            onClick={() => generate(true)}
          >
            <RotateCcw aria-hidden="true" className="size-4" />
            다시 생성
          </button>
        )}
        {!canGenerate && status.status === "none" && (
          <p className="text-body text-muted-foreground">
            보고서 생성은 워크스페이스 소유자 또는 작업자가 할 수 있습니다.
          </p>
        )}
      </div>
      {status.expires_at && (
        <p className="text-caption text-muted-foreground">
          보고서는 {formatSeoulDateTime(status.expires_at)}까지 보관된 뒤 자동
          삭제됩니다.
        </p>
      )}

      {error && <ErrorAlert>{error}</ErrorAlert>}
      <p
        role="status"
        aria-live="polite"
        className="text-body text-status-safe"
      >
        {notice}
      </p>

      <ul className="grid gap-3 md:grid-cols-3">
        {status.reports.map((report) => (
          <li
            key={report.report_type}
            className="flex flex-col gap-3 rounded-md border border-border bg-card p-4"
          >
            <div className="flex items-start gap-2">
              <FileText
                aria-hidden="true"
                className="mt-0.5 size-5 shrink-0 text-primary"
              />
              <div className="min-w-0">
                <h3 className="text-h3">{report.title}</h3>
                <p className="text-caption text-muted-foreground">
                  {REPORT_DESCRIPTIONS[report.report_type]}
                </p>
              </div>
            </div>
            {report.docx && report.pdf ? (
              <div className="mt-auto flex flex-wrap gap-2">
                {[
                  { label: "DOCX", file: report.docx },
                  { label: "PDF", file: report.pdf },
                ].map(({ label, file }) => (
                  <a
                    key={label}
                    href={file.download_url}
                    className={buttonStyles.secondary}
                    aria-label={`${report.title} ${label} 내려받기 (${formatBytes(file.file_size_bytes)})`}
                  >
                    <Download aria-hidden="true" className="size-4" />
                    {label}
                    <span className="text-caption text-muted-foreground">
                      {formatBytes(file.file_size_bytes)}
                    </span>
                  </a>
                ))}
              </div>
            ) : (
              <p className="mt-auto text-caption text-muted-foreground">
                {busy ? "조판 중" : "아직 생성되지 않았습니다"}
              </p>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function RetentionBadge({ status }: { status: ReportStatus }) {
  if (status.raw_logs_purged) {
    return (
      <p className="flex items-start gap-2 rounded-md border border-status-safe px-3 py-2 text-body">
        <CircleCheck
          aria-hidden="true"
          className="mt-0.5 size-4 shrink-0 text-status-safe"
        />
        원본 진단 로그가
        {status.raw_logs_purged_at
          ? ` ${formatSeoulDateTime(status.raw_logs_purged_at)}에`
          : ""}{" "}
        영구 삭제되었습니다. 판정 결과와 보고서는 그대로 열람할 수 있습니다.
      </p>
    );
  }
  return (
    <p className="flex items-start gap-2 rounded-md border border-border px-3 py-2 text-body">
      <ShieldCheck
        aria-hidden="true"
        className="mt-0.5 size-4 shrink-0 text-primary"
      />
      {status.zero_retention_active
        ? "제로 리텐션 사용 중: 3종 일괄 다운로드가 끝나면 원본 진단 로그를 영구 삭제합니다. 내려받지 않아도 보고서 생성 24시간 뒤 자동 삭제됩니다."
        : "제로 리텐션 사용 안 함: 원본 진단 로그를 보관합니다."}
    </p>
  );
}

/** 일괄 ZIP 다운로드. 제로 리텐션이면 확인을 받고, 다운로드가 끝난 뒤 원본 파기를 요청한다. */
function BundleDownload({
  runId,
  url,
  purgeOnDownload,
  onPurged,
  onError,
}: {
  runId: string;
  url: string;
  purgeOnDownload: boolean;
  onPurged: (count: number) => void;
  onError: (message: string | null) => void;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const [pending, setPending] = useState(false);

  if (!purgeOnDownload) {
    return (
      <a href={url} className={buttonStyles.primary}>
        <Download aria-hidden="true" className="size-4" />
        3종 보고서 일괄 다운로드 (ZIP)
      </a>
    );
  }

  const confirm = async () => {
    setPending(true);
    onError(null);
    try {
      const response = await fetch(url, { cache: "no-store" });
      if (!response.ok) {
        onError(await errorMessage(response, "보고서를 내려받지 못했습니다."));
        return;
      }
      const blob = await response.blob();
      const name =
        /filename\*=UTF-8''([^;]+)/.exec(
          response.headers.get("Content-Disposition") ?? "",
        )?.[1] ?? "reports.zip";
      const href = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = href;
      link.download = decodeURIComponent(name);
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(href), 10_000);

      const purge = await fetch(`/api/assessments/${runId}/reports/purge-raw`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm_purge: true }),
      });
      if (!purge.ok) {
        onError(
          `보고서는 내려받았지만 원본 파기에 실패했습니다: ${await errorMessage(purge, "다시 시도해 주세요.")}`,
        );
        return;
      }
      const result = purgeSchema.safeParse(await purge.json());
      dialogRef.current?.close();
      onPurged(result.success ? result.data.purged_log_count : 0);
    } catch {
      onError("네트워크 오류로 내려받지 못했습니다. 다시 시도해 주세요.");
    } finally {
      setPending(false);
    }
  };

  return (
    <>
      <button
        type="button"
        className={buttonStyles.primary}
        aria-haspopup="dialog"
        onClick={() => dialogRef.current?.showModal()}
      >
        <Download aria-hidden="true" className="size-4" />
        3종 보고서 일괄 다운로드 (ZIP)
      </button>
      <dialog
        ref={dialogRef}
        aria-labelledby={titleId}
        className="m-auto w-[calc(100%-2rem)] max-w-lg rounded-md border border-border bg-card p-0 text-foreground backdrop:bg-background/80"
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-2">
          <h2 id={titleId} className="text-h3">
            원본 진단 로그 영구 삭제 안내
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
        <div className="flex flex-col gap-4 p-4">
          <p className="text-body">
            다운로드가 완료되면 워크스페이스 보안 정책에 따라 원본 진단 로그
            파일이 영구 삭제됩니다. 계속 진행하시겠습니까?
          </p>
          <p className="text-caption text-muted-foreground">
            판정 결과와 보고서(24시간 보관)는 남아 있어 다시 내려받을 수
            있습니다. 원본 로그는 복구할 수 없습니다.
          </p>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              className={buttonStyles.secondary}
              onClick={() => dialogRef.current?.close()}
            >
              취소
            </button>
            <button
              type="button"
              className={buttonStyles.primary}
              disabled={pending}
              onClick={confirm}
            >
              {pending && (
                <LoaderCircle
                  aria-hidden="true"
                  className="size-4 motion-safe:animate-spin"
                />
              )}
              {pending ? "내려받는 중…" : "내려받고 원본 삭제"}
            </button>
          </div>
        </div>
      </dialog>
    </>
  );
}

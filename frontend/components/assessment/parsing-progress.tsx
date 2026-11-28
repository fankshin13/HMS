"use client";

import { LoaderCircle, RotateCcw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { z } from "zod";
import { ErrorAlert } from "@/components/common/alert";
import { buttonStyles } from "@/components/common/button-styles";

const POLL_MS = 2000;

const statusSchema = z.object({
  status: z.string(),
  progress_percentage: z.number(),
  total_assets: z.number(),
  processed_assets: z.number(),
});

type Progress = z.infer<typeof statusSchema>;

/** 파싱 진행률을 2초마다 확인하고, 끝나면 서버 화면을 새로 그린다. */
export function ParsingProgress({
  runId,
  initial,
}: {
  runId: string;
  initial: Progress;
}) {
  const router = useRouter();
  const [progress, setProgress] = useState(initial);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const timer = window.setInterval(async () => {
      try {
        const response = await fetch(`/api/assessments/${runId}/status`, {
          cache: "no-store",
        });
        const parsed = statusSchema.safeParse(await response.json());
        if (!response.ok || !parsed.success)
          throw new Error(`status ${response.status}`);
        if (cancelled) return;
        setFailed(false);
        setProgress(parsed.data);
        if (
          parsed.data.status !== "queued" &&
          parsed.data.status !== "parsing"
        ) {
          window.clearInterval(timer);
          router.refresh();
        }
      } catch {
        if (cancelled) return;
        setFailed(true); // 다시 시도 버튼으로 폴링을 재개한다
        window.clearInterval(timer);
      }
    }, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [runId, router, attempt]);

  return (
    <section
      aria-labelledby="progress-title"
      className="flex flex-col gap-3 rounded-md border border-border bg-card p-4"
    >
      <h2 id="progress-title" className="flex items-center gap-2 text-h3">
        <LoaderCircle
          aria-hidden="true"
          className="size-4 motion-safe:animate-spin"
        />
        진단 로그 파싱 및 KISA 표준 기준 자동 판정 중…
      </h2>
      <progress
        max={100}
        value={progress.progress_percentage}
        aria-label="판정 진행률"
        className="h-2 w-full accent-primary-action"
      />
      <p
        role="status"
        aria-live="polite"
        className="text-body text-muted-foreground"
      >
        {progress.status === "queued"
          ? "분석 대기열에서 순서를 기다리고 있습니다."
          : `자산 ${progress.total_assets}대 중 ${progress.processed_assets}대 판정 완료 (${progress.progress_percentage}%)`}
      </p>
      {failed && (
        <div className="flex flex-col items-start gap-2">
          <ErrorAlert>
            진단 상태를 불러오지 못했습니다. 잠시 후 다시 시도해 주세요.
          </ErrorAlert>
          <button
            type="button"
            className={buttonStyles.secondary}
            onClick={() => {
              setFailed(false);
              setAttempt((n) => n + 1);
            }}
          >
            <RotateCcw aria-hidden="true" className="size-4" />
            다시 시도
          </button>
        </div>
      )}
    </section>
  );
}

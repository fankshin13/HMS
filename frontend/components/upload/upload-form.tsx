"use client";

import {
  FileUp,
  LoaderCircle,
  RotateCcw,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import Link from "next/link";
import { type ChangeEvent, type DragEvent, useRef, useState } from "react";
import { ErrorAlert } from "@/components/common/alert";
import { buttonStyles } from "@/components/common/button-styles";
import { inputStyles, labelStyles } from "@/components/common/form-styles";
import {
  ACCEPTED_EXTENSIONS,
  UPLOAD_ERROR_MESSAGES,
  UPLOAD_LIMITS,
  type UploadErrorCode,
  extensionOf,
} from "@/lib/upload/limits";
import { LOG_PROBLEM_MESSAGES } from "@/lib/upload/log-header";
import type { PreparedUpload } from "@/lib/upload/prepare";
import type { PrepareRequest } from "@/lib/upload/prepare.worker";
import {
  type UploadResponse,
  uploadErrorSchema,
  uploadResponseSchema,
} from "@/lib/upload/response";
import { formatBytes } from "@/lib/format";

type Phase =
  | { kind: "idle" }
  | { kind: "preparing"; fileName: string }
  | { kind: "ready"; prepared: PreparedUpload }
  | { kind: "uploading"; prepared: PreparedUpload; percent: number }
  | { kind: "duplicate"; prepared: PreparedUpload }
  | { kind: "done"; response: UploadResponse };

type WorkerReply =
  | { ok: true; result: PreparedUpload }
  | { ok: false; code: UploadErrorCode | "unknown" };

const OS_LABELS = { linux: "Linux", windows: "Windows" } as const;
const UPLOAD_FAILED =
  "진단 파일 업로드 중 오류가 발생했습니다. 네트워크 상태를 확인하고 다시 시도해 주세요.";

function checkFile(file: File): string | null {
  if (
    !(ACCEPTED_EXTENSIONS as readonly string[]).includes(extensionOf(file.name))
  ) {
    return UPLOAD_ERROR_MESSAGES.unsupported_type;
  }
  if (file.size > UPLOAD_LIMITS.maxUploadBytes)
    return UPLOAD_ERROR_MESSAGES.too_large;
  return null;
}

/** 브라우저 작업 스레드에서 압축 해제·마스킹·머리말 검사를 수행한다. */
function prepareInWorker(
  file: File,
  maskSensitive: boolean,
): Promise<WorkerReply> {
  return file.arrayBuffer().then(
    (bytes) =>
      new Promise((resolve) => {
        const worker = new Worker(
          new URL("../../lib/upload/prepare.worker.ts", import.meta.url),
          { type: "module" },
        );
        worker.addEventListener(
          "message",
          (event: MessageEvent<WorkerReply>) => {
            resolve(event.data);
            worker.terminate();
          },
        );
        worker.addEventListener("error", () => {
          resolve({ ok: false, code: "unknown" });
          worker.terminate();
        });
        const request: PrepareRequest = {
          fileName: file.name,
          bytes,
          masking: { maskIp: maskSensitive, maskUsernames: maskSensitive },
        };
        worker.postMessage(request, [bytes]);
      }),
  );
}

/** 진행률을 알 수 있도록 XHR 로 전송한다(fetch 는 업로드 진행률을 주지 않는다). */
function send(
  form: FormData,
  onProgress: (percent: number) => void,
): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/assessments/upload");
    xhr.responseType = "json";
    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable)
        onProgress(Math.round((event.loaded / event.total) * 100));
    });
    xhr.addEventListener("load", () =>
      resolve({ status: xhr.status, body: xhr.response }),
    );
    xhr.addEventListener("error", () => reject(new Error("network")));
    xhr.send(form);
  });
}

export function UploadForm({ defaultTitle }: { defaultTitle: string }) {
  const [title, setTitle] = useState(defaultTitle);
  const [maskSensitive, setMaskSensitive] = useState(true);
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const lastFile = useRef<File | null>(null);
  const busy = phase.kind === "preparing" || phase.kind === "uploading";

  async function choose(file: File) {
    setError(null);
    const problem = checkFile(file);
    if (problem) {
      setError(problem);
      setPhase({ kind: "idle" });
      return;
    }
    lastFile.current = file;
    setPhase({ kind: "preparing", fileName: file.name });
    const reply = await prepareInWorker(file, maskSensitive);
    if (!reply.ok) {
      setError(
        reply.code === "unknown"
          ? "파일을 처리하지 못했습니다. 다른 파일로 다시 시도해 주세요."
          : UPLOAD_ERROR_MESSAGES[reply.code],
      );
      setPhase({ kind: "idle" });
      return;
    }
    setPhase({ kind: "ready", prepared: reply.result });
  }

  async function upload(prepared: PreparedUpload, allowDuplicate = false) {
    setError(null);
    setPhase({ kind: "uploading", prepared, percent: 0 });
    const form = new FormData();
    form.set("title", title);
    form.set("allowDuplicate", String(allowDuplicate));
    form.set(
      "file",
      new File([new Uint8Array(prepared.payload)], prepared.payloadName),
    );
    try {
      const { status, body } = await send(form, (percent) =>
        setPhase({ kind: "uploading", prepared, percent }),
      );
      const ok = uploadResponseSchema.safeParse(body);
      if (status === 201 && ok.success) {
        setPhase({ kind: "done", response: ok.data });
        return;
      }
      const failure = uploadErrorSchema.safeParse(body);
      if (
        status === 409 &&
        failure.success &&
        failure.data.error.code === "duplicate"
      ) {
        setPhase({ kind: "duplicate", prepared });
        return;
      }
      setError(failure.success ? failure.data.error.message : UPLOAD_FAILED);
    } catch {
      setError(UPLOAD_FAILED);
    }
    setPhase({ kind: "ready", prepared });
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files[0];
    if (file && !busy) void choose(file);
  }

  function onPick(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (file) void choose(file);
  }

  if (phase.kind === "done") return <UploadResult response={phase.response} />;

  const prepared =
    phase.kind === "ready" ||
    phase.kind === "uploading" ||
    phase.kind === "duplicate"
      ? phase.prepared
      : null;

  return (
    <div className="flex flex-col gap-6">
      <div className="grid gap-4 lg:grid-cols-[1fr_auto] lg:items-end">
        <div className="flex flex-col gap-2">
          <label htmlFor="assessment-title" className={labelStyles}>
            진단명
          </label>
          <input
            id="assessment-title"
            value={title}
            maxLength={200}
            required
            disabled={busy}
            onChange={(event) => setTitle(event.target.value)}
            className={inputStyles}
          />
        </div>
        <label className="flex min-h-11 cursor-pointer items-center gap-3 rounded-md border border-border px-3">
          <input
            type="checkbox"
            role="switch"
            checked={maskSensitive}
            disabled={busy}
            onChange={(event) => {
              setMaskSensitive(event.target.checked);
              // 마스킹 설정이 바뀌면 파일을 다시 준비해야 하므로 선택을 초기화한다
              if (phase.kind === "ready" || phase.kind === "duplicate")
                setPhase({ kind: "idle" });
            }}
            className="size-5 accent-primary-action"
          />
          <span className="text-body">
            전송 전 비식별화{" "}
            <span className="text-muted-foreground">
              (사설 IP·계정명 {maskSensitive ? "켜짐" : "꺼짐"})
            </span>
          </span>
        </label>
      </div>

      <div
        onDragOver={(event) => {
          event.preventDefault();
          if (!busy) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`flex flex-col items-center gap-3 rounded-md border-2 border-dashed px-4 py-10 text-center ${
          dragging
            ? "border-primary bg-primary/10"
            : "border-muted-foreground bg-card"
        }`}
      >
        <FileUp aria-hidden="true" className="size-8 text-muted-foreground" />
        <p className="text-h3">점검 결과 파일을 이곳에 끌어다 놓으세요</p>
        <p className="text-body text-muted-foreground">
          50MB 이하의 .zip, .txt, .log 파일
        </p>
        <input
          ref={fileInput}
          type="file"
          accept={ACCEPTED_EXTENSIONS.join(",")}
          className="sr-only"
          tabIndex={-1}
          aria-hidden="true"
          onChange={onPick}
        />
        <button
          type="button"
          className={buttonStyles.secondary}
          disabled={busy}
          onClick={() => fileInput.current?.click()}
        >
          파일 선택
        </button>
      </div>

      <div role="status" aria-live="polite" className="flex flex-col gap-2">
        {phase.kind === "preparing" && (
          <p className="flex items-center gap-2 text-body">
            <LoaderCircle
              aria-hidden="true"
              className="size-4 shrink-0 motion-safe:animate-spin"
            />
            {maskSensitive
              ? "브라우저에서 사설 IP 및 계정 정보를 안전하게 마스킹 중입니다…"
              : "브라우저에서 파일 형식을 확인하는 중입니다…"}
          </p>
        )}
        {phase.kind === "uploading" && (
          <>
            <p className="text-body">
              서버로 데이터를 안전하게 전송 중입니다… {phase.percent}%
            </p>
            <progress
              max={100}
              value={phase.percent}
              className="h-2 w-full accent-primary-action"
              aria-label="업로드 진행률"
            />
          </>
        )}
      </div>

      {error && (
        <div className="flex flex-col items-start gap-2">
          <ErrorAlert>{error}</ErrorAlert>
          {prepared && (
            <button
              type="button"
              className={buttonStyles.secondary}
              onClick={() => void upload(prepared)}
            >
              <RotateCcw aria-hidden="true" className="size-4" />
              다시 시도
            </button>
          )}
        </div>
      )}

      {phase.kind === "duplicate" && (
        <section
          role="alert"
          className="flex flex-col gap-3 rounded-md border border-status-warning p-4"
        >
          <p className="flex items-start gap-2 text-body">
            <TriangleAlert
              aria-hidden="true"
              className="mt-0.5 size-4 shrink-0 text-status-warning"
            />
            같은 파일이 10분 안에 이미 업로드되었습니다. 그래도 새 진단 차수로
            등록할까요?
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className={buttonStyles.primary}
              onClick={() => void upload(phase.prepared, true)}
            >
              새 진단으로 등록
            </button>
            <Link href="/assessments" className={buttonStyles.secondary}>
              진단 차수 목록 보기
            </Link>
          </div>
        </section>
      )}

      {prepared && (
        <PreparedPreview prepared={prepared} masked={maskSensitive} />
      )}

      {prepared && phase.kind !== "duplicate" && (
        <button
          type="button"
          className={`${buttonStyles.primary} self-start`}
          disabled={busy || title.trim().length === 0}
          onClick={() => void upload(prepared)}
        >
          {phase.kind === "uploading" && (
            <LoaderCircle
              aria-hidden="true"
              className="size-4 motion-safe:animate-spin"
            />
          )}
          {phase.kind === "uploading"
            ? "업로드 중…"
            : "진단 시작 및 파일 업로드"}
        </button>
      )}
    </div>
  );
}

function PreparedPreview({
  prepared,
  masked,
}: {
  prepared: PreparedUpload;
  masked: boolean;
}) {
  const quarantined = prepared.logs.filter(
    (log) => log.parseStatus !== "success",
  );
  return (
    <section aria-labelledby="preview-title" className="flex flex-col gap-3">
      <h2 id="preview-title" className="text-h3">
        업로드 전 확인{" "}
        <span className="text-muted-foreground">
          {prepared.logs.length}개 파일
        </span>
      </h2>
      <p className="flex items-start gap-2 text-body">
        <ShieldCheck
          aria-hidden="true"
          className="mt-0.5 size-4 shrink-0 text-status-safe"
        />
        {masked
          ? `사설 IP ${prepared.maskedIpCount}건, 계정명 ${prepared.maskedUserCount}건을 브라우저에서 가명으로 바꿨습니다. 원본 값은 서버로 전송되지 않습니다.`
          : "비식별화가 꺼져 있어 파일 내용이 그대로 전송됩니다."}
      </p>
      {prepared.examples.length > 0 && (
        <details className="rounded-md border border-border p-3">
          <summary className="min-h-11 cursor-pointer content-center text-body">
            바뀐 값 예시 보기 (이 화면에만 표시)
          </summary>
          <ul className="mt-2 flex flex-col gap-1 font-mono text-caption">
            {prepared.examples.map((example) => (
              <li key={example.masked} className="break-all">
                {example.original} → {example.masked}
              </li>
            ))}
          </ul>
        </details>
      )}
      {quarantined.length > 0 && (
        <p className="flex items-start gap-2 text-body">
          <TriangleAlert
            aria-hidden="true"
            className="mt-0.5 size-4 shrink-0 text-status-warning"
          />
          일부 파일의 형식이 표준 스크립트와 일치하지 않습니다. 해당 자산은
          격리되어 수동 검토로 전환되고, 나머지 파일은 정상 처리됩니다.
        </p>
      )}
      <AssetTable
        rows={prepared.logs.map((log) => ({
          key: log.fileName,
          hostname: log.hostname,
          os: log.osType,
          ip: log.detectedIp,
          fileName: log.fileName,
          size: log.sizeBytes,
          ok: log.parseStatus === "success",
          problem: log.problem
            ? `${LOG_PROBLEM_MESSAGES[log.problem]}${log.problemLine ? ` (${log.problemLine}번째 줄)` : ""}`
            : null,
        }))}
      />
    </section>
  );
}

type Row = {
  key: string;
  hostname: string | null;
  os: "linux" | "windows" | null;
  ip: string | null;
  fileName: string;
  size?: number;
  ok: boolean;
  problem: string | null;
};

function AssetTable({ rows }: { rows: Row[] }) {
  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full min-w-[560px] text-left text-body">
        <thead className="bg-card text-muted-foreground">
          <tr>
            <th scope="col" className="px-3 py-2 font-medium">
              호스트명
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              OS
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              IP
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              파일
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              상태
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {rows.map((row) => (
            <tr key={row.key}>
              <td className="px-3 py-2 font-medium">
                {row.hostname ?? "식별 불가"}
              </td>
              <td className="px-3 py-2">{row.os ? OS_LABELS[row.os] : "—"}</td>
              <td className="px-3 py-2 font-mono text-caption">
                {row.ip ?? "—"}
              </td>
              <td className="px-3 py-2 break-all">
                {row.fileName}
                {row.size !== undefined && (
                  <span className="block text-caption text-muted-foreground">
                    {formatBytes(row.size)}
                  </span>
                )}
              </td>
              <td className="px-3 py-2">
                {row.ok ? (
                  <span className="text-status-safe">정상</span>
                ) : (
                  <span>
                    <span className="font-medium text-status-warning">
                      수동 검토 필요
                    </span>
                    {row.problem && (
                      <span className="block text-caption text-muted-foreground">
                        {row.problem}
                      </span>
                    )}
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UploadResult({ response }: { response: UploadResponse }) {
  const { result } = response;
  return (
    <section aria-labelledby="result-title" className="flex flex-col gap-4">
      <div role="status" className="flex flex-col gap-1">
        <h2 id="result-title" className="text-h2">
          업로드가 완료되었습니다
        </h2>
        <p className="text-body text-muted-foreground">
          자산 {result.total_assets}대를 식별했습니다
          {result.quarantined_files > 0
            ? `, ${result.quarantined_files}개 파일은 수동 검토로 격리되었습니다`
            : ""}
          . 분석 대기열에 등록되었습니다.
        </p>
      </div>
      <AssetTable
        rows={result.assets_preview.map((asset, index) => ({
          key: `${asset.file_name}-${index}`,
          hostname: asset.hostname,
          os: asset.os_type,
          ip: asset.detected_ip,
          fileName: asset.file_name,
          ok: asset.parse_status === "success",
          problem: asset.error_details
            ? `${asset.error_details.message}${asset.error_details.line ? ` (${asset.error_details.line}번째 줄)` : ""}`
            : null,
        }))}
      />
      <div className="flex flex-wrap gap-2">
        <Link
          href={`/assessments/${result.assessment_run_id}`}
          className={buttonStyles.primary}
        >
          진단 결과 화면으로 이동
        </Link>
        <Link href="/assessments" className={buttonStyles.secondary}>
          진단 차수 목록
        </Link>
      </div>
    </section>
  );
}

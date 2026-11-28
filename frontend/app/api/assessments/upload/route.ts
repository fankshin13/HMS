import { randomUUID } from "node:crypto";
import { type NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { extractLogFiles, sha256Hex } from "@/lib/upload/archive";
import { UPLOAD_LIMITS, UploadError } from "@/lib/upload/limits";
import { LOG_PROBLEM_MESSAGES, parseLog } from "@/lib/upload/log-header";
import { createClient, getAuthUserId } from "@/lib/supabase/server";
import { getMembership } from "@/lib/workspace";

export const runtime = "nodejs";

const BUCKET = "diagnostic-raw";
const MULTIPART_OVERHEAD = 1024 * 1024;

const fieldsSchema = z.object({
  title: z
    .string()
    .trim()
    .min(1, "진단명을 입력해 주세요.")
    .max(200, "진단명은 200자 이내로 입력해 주세요."),
  allowDuplicate: z.enum(["true", "false"]).optional(),
});

function fail(status: number, code: string, message: string) {
  return NextResponse.json({ error: { code, message } }, { status });
}

function storageName(index: number, name: string): string {
  const safe = name.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 100);
  return `${String(index + 1).padStart(3, "0")}_${safe}`;
}

/** 진단 결과 파일 업로드: 인증 → 크기·형식 검사 → 로그별 머리말 검사 → 비공개 저장 → 진단 차수 등록 */
export async function POST(request: NextRequest) {
  const started = performance.now();

  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (declaredLength > UPLOAD_LIMITS.maxUploadBytes + MULTIPART_OVERHEAD) {
    return fail(413, "too_large", "파일 크기는 최대 50MB까지 지원됩니다.");
  }

  const supabase = await createClient();
  const userId = await getAuthUserId(supabase);
  if (!userId) return fail(401, "unauthorized", "로그인이 필요합니다.");
  const membership = await getMembership(supabase, userId);
  if (!membership || membership.role === "viewer") {
    return fail(
      403,
      "forbidden",
      "진단 파일은 워크스페이스 소유자 또는 작업자만 업로드할 수 있습니다.",
    );
  }

  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return fail(
      400,
      "bad_request",
      "업로드 요청을 읽을 수 없습니다. 다시 시도해 주세요.",
    );
  }
  const fields = fieldsSchema.safeParse({
    title: form.get("title"),
    allowDuplicate: form.get("allowDuplicate") ?? undefined,
  });
  if (!fields.success) {
    return fail(
      400,
      "invalid_input",
      fields.error.issues[0]?.message ?? "입력값을 확인해 주세요.",
    );
  }
  const file = form.get("file");
  if (!(file instanceof File))
    return fail(400, "missing_file", "업로드할 파일을 선택해 주세요.");
  if (file.size > UPLOAD_LIMITS.maxUploadBytes) {
    return fail(413, "too_large", "파일 크기는 최대 50MB까지 지원됩니다.");
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  let logs;
  try {
    logs = extractLogFiles(file.name, bytes);
  } catch (error) {
    if (error instanceof UploadError) {
      const status =
        error.code === "unsupported_type"
          ? 415
          : error.code === "too_large"
            ? 413
            : 400;
      return fail(status, error.code, error.message);
    }
    throw error;
  }

  const sha256 = await sha256Hex(bytes);
  const runId = randomUUID();
  const prefix = `${membership.tenantId}/${runId}`;
  const entries = logs.map((log, index) => {
    const parsed = parseLog(log.text);
    return {
      log,
      path: `${prefix}/${storageName(index, log.name)}`,
      record: {
        file_name: log.name,
        file_size_bytes: log.sizeBytes,
        storage_path: `${prefix}/${storageName(index, log.name)}`,
        parse_status: parsed.parseStatus,
        hostname: parsed.hostname,
        os_type: parsed.osType,
        os_version: parsed.osVersion,
        detected_ip: parsed.detectedIp,
        quarantined_error_lines: parsed.quarantinedErrorLines,
        error_details: parsed.problem
          ? {
              reason: parsed.problem,
              line: parsed.problemLine,
              message: LOG_PROBLEM_MESSAGES[parsed.problem],
            }
          : null,
      },
    };
  });

  const storage = supabase.storage.from(BUCKET);
  const uploaded: string[] = [];
  const cleanup = async () => {
    if (uploaded.length === 0) return;
    const { error } = await storage.remove(uploaded);
    if (error)
      console.error("업로드 정리 실패", { runId, error: error.message });
  };

  for (const entry of entries) {
    const { error } = await storage.upload(
      entry.path,
      new Blob([entry.log.text], { type: "text/plain" }),
      {
        contentType: "text/plain",
        upsert: false,
      },
    );
    if (error) {
      console.error("원본 로그 저장 실패", { runId, error: error.message });
      await cleanup();
      return fail(
        502,
        "storage_failed",
        "진단 파일 업로드 중 오류가 발생했습니다. 네트워크 상태를 확인하고 다시 시도해 주세요.",
      );
    }
    uploaded.push(entry.path);
  }

  const { data, error } = await supabase.rpc("register_assessment_upload", {
    p_run_id: runId,
    p_tenant_id: membership.tenantId,
    p_title: fields.data.title,
    p_sha256: sha256,
    p_logs: entries.map((entry) => entry.record),
    p_allow_duplicate: fields.data.allowDuplicate === "true",
  });
  if (error) {
    await cleanup();
    if (error.code === "23505") {
      return fail(
        409,
        "duplicate",
        "같은 파일이 10분 안에 이미 업로드되었습니다. 새 진단으로 다시 등록할지 선택해 주세요.",
      );
    }
    if (error.code === "42501")
      return fail(403, "forbidden", "진단 파일을 업로드할 권한이 없습니다.");
    if (error.code === "22023")
      return fail(400, "invalid_input", error.message);
    console.error("진단 차수 등록 실패", { runId, code: error.code });
    return fail(
      500,
      "register_failed",
      "진단 파일 업로드 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.",
    );
  }

  return NextResponse.json(
    { result: data, elapsed_ms: Math.round(performance.now() - started) },
    { status: 201 },
  );
}

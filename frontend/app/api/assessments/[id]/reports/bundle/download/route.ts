import { zipSync } from "fflate";
import { type NextRequest } from "next/server";
import { z } from "zod";
import { apiError } from "@/lib/assessments/api";
import { fetchReportFiles, seoulCompactDate } from "@/lib/reports/download";
import {
  REPORT_FORMATS,
  REPORT_TYPES,
  contentDisposition,
  reportFileName,
} from "@/lib/reports/reports";
import { createClient, getAuthUserId } from "@/lib/supabase/server";

/** 3종 × 2형식 6개 파일을 ZIP 하나로 (owner·operator·viewer). DOCX·PDF 는 이미 압축돼 있어 저장만 한다. */
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const id = z
    .string()
    .uuid()
    .safeParse((await params).id);
  if (!id.success)
    return apiError(404, "not_found", "보고서를 찾을 수 없습니다.");
  const supabase = await createClient();
  if (!(await getAuthUserId(supabase)))
    return apiError(401, "unauthorized", "로그인이 필요합니다.");

  const wanted = REPORT_TYPES.flatMap((type) =>
    REPORT_FORMATS.map((format) => ({ type, format })),
  );
  const result = await fetchReportFiles(supabase, id.data, wanted);
  if (result instanceof Response) return result;

  const date = seoulCompactDate();
  const entries: Record<string, Uint8Array> = {};
  for (const file of result.files) {
    entries[reportFileName(file.type, result.runTitle, date, file.format)] =
      file.bytes;
  }
  const zip = zipSync(entries, { level: 0 });
  return new Response(Buffer.from(zip), {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": contentDisposition(
        `진단보고서_3종일괄_${date}.zip`,
      ),
      "Content-Length": String(zip.byteLength),
      "Cache-Control": "no-store",
    },
  });
}

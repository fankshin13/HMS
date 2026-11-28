import { type NextRequest } from "next/server";
import { z } from "zod";
import { apiError } from "@/lib/assessments/api";
import { fetchReportFiles, seoulCompactDate } from "@/lib/reports/download";
import {
  CONTENT_TYPES,
  contentDisposition,
  reportFileName,
  reportFormatSchema,
  reportTypeSchema,
} from "@/lib/reports/reports";
import { createClient, getAuthUserId } from "@/lib/supabase/server";

const paramsSchema = z.object({
  id: z.string().uuid(),
  type: reportTypeSchema,
});

/** 보고서 한 개 다운로드 (owner·operator·viewer). ?format=docx|pdf */
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string; type: string }> },
) {
  const parsed = paramsSchema.safeParse(await params);
  if (!parsed.success)
    return apiError(404, "not_found", "보고서를 찾을 수 없습니다.");
  const format = reportFormatSchema.safeParse(
    request.nextUrl.searchParams.get("format"),
  );
  if (!format.success)
    return apiError(
      422,
      "invalid_format",
      "format 은 docx 또는 pdf 여야 합니다.",
    );

  const supabase = await createClient();
  if (!(await getAuthUserId(supabase)))
    return apiError(401, "unauthorized", "로그인이 필요합니다.");

  const result = await fetchReportFiles(supabase, parsed.data.id, [
    { type: parsed.data.type, format: format.data },
  ]);
  if (result instanceof Response) return result;
  const [file] = result.files;
  if (!file) return apiError(404, "not_found", "보고서를 찾을 수 없습니다.");
  const name = reportFileName(
    file.type,
    result.runTitle,
    seoulCompactDate(),
    file.format,
  );
  return new Response(Buffer.from(file.bytes), {
    headers: {
      "Content-Type": CONTENT_TYPES[file.format],
      "Content-Disposition": contentDisposition(name),
      "Content-Length": String(file.bytes.byteLength),
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

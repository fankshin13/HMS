import { z } from "zod";

/** /api/assessments/upload 응답 */
export const uploadResponseSchema = z.object({
  result: z.object({
    assessment_run_id: z.string().uuid(),
    title: z.string(),
    status: z.string(),
    total_assets: z.number(),
    quarantined_files: z.number(),
    assets_preview: z.array(
      z.object({
        asset_id: z.string().nullable(),
        hostname: z.string().nullable(),
        os_type: z.enum(["linux", "windows"]).nullable(),
        detected_ip: z.string().nullable(),
        file_name: z.string(),
        parse_status: z.enum(["success", "partial_error", "failed"]),
        error_details: z
          .object({ message: z.string(), line: z.number().nullable() })
          .nullable(),
      }),
    ),
  }),
  elapsed_ms: z.number(),
});

export const uploadErrorSchema = z.object({
  error: z.object({ code: z.string(), message: z.string() }),
});

export type UploadResponse = z.infer<typeof uploadResponseSchema>;

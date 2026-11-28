import "server-only";

import { NextResponse } from "next/server";
import { z } from "zod";

export function apiError(status: number, code: string, message: string) {
  return NextResponse.json({ error: { code, message } }, { status });
}

export const routeIdsSchema = z.object({
  id: z.string().uuid(),
  itemId: z.string().uuid(),
});

export const NOT_FOUND = "점검 항목을 찾을 수 없습니다.";

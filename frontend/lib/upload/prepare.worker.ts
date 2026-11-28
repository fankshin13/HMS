/// <reference lib="webworker" />
// 큰 파일의 압축 해제·마스킹이 화면을 멈추지 않도록 별도 스레드에서 처리한다.
import { UploadError } from "./limits";
import type { MaskingConfig } from "./masking";
import { prepareUpload } from "./prepare";

export type PrepareRequest = {
  fileName: string;
  bytes: ArrayBuffer;
  masking: MaskingConfig;
};

declare const self: DedicatedWorkerGlobalScope;

self.addEventListener(
  "message",
  async (event: MessageEvent<PrepareRequest>) => {
    const { fileName, bytes, masking } = event.data;
    try {
      const result = await prepareUpload(
        fileName,
        new Uint8Array(bytes),
        masking,
      );
      self.postMessage({ ok: true, result }, [result.payload.buffer]);
    } catch (error) {
      self.postMessage({
        ok: false,
        code: error instanceof UploadError ? error.code : "unknown",
      });
    }
  },
);

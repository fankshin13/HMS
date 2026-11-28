import "server-only";

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

export type ScriptPackage = {
  os: "linux" | "windows";
  title: string;
  supported: string;
  fileName: string;
  href: string;
  version: string;
  sha256: string;
  sizeBytes: number;
  steps: { label: string; command: string }[];
};

const SCRIPTS_DIR = path.join(process.cwd(), "public", "scripts");

const DEFINITIONS = [
  {
    os: "linux",
    title: "Linux 점검 스크립트",
    supported: "CentOS · RHEL · Rocky · Ubuntu · Debian",
    fileName: "kisa_check_linux.sh",
    steps: (file: string) => [
      { label: "체크섬 확인", command: `sha256sum ${file}` },
      { label: "root 권한으로 실행", command: `sudo bash ${file}` },
    ],
  },
  {
    os: "windows",
    title: "Windows 점검 스크립트",
    supported: "Windows Server 2016 이상",
    fileName: "kisa_check_windows.bat",
    steps: (file: string) => [
      {
        label: "체크섬 확인 (명령 프롬프트)",
        command: `certutil -hashfile ${file} SHA256`,
      },
      { label: "관리자 권한 명령 프롬프트에서 실행", command: file },
    ],
  },
] as const;

function versionOf(content: string): string {
  return (
    /SCRIPT_VERSION="?=?([0-9]+\.[0-9]+\.[0-9]+)/.exec(content)?.[1] ??
    "알 수 없음"
  );
}

/** 배포 중인 공식 스크립트 목록. 파일이 없는 OS 는 목록에서 빠진다. */
export async function listScriptPackages(): Promise<ScriptPackage[]> {
  const packages = await Promise.all(
    DEFINITIONS.map(async (definition): Promise<ScriptPackage | null> => {
      let bytes: Buffer;
      try {
        bytes = await readFile(path.join(SCRIPTS_DIR, definition.fileName));
      } catch (error) {
        if (
          error instanceof Error &&
          "code" in error &&
          error.code === "ENOENT"
        )
          return null;
        throw error;
      }
      return {
        os: definition.os,
        title: definition.title,
        supported: definition.supported,
        fileName: definition.fileName,
        href: `/scripts/${definition.fileName}`,
        version: versionOf(bytes.toString("utf8")),
        sha256: createHash("sha256").update(bytes).digest("hex"),
        sizeBytes: bytes.byteLength,
        steps: definition.steps(definition.fileName),
      };
    }),
  );
  return packages.filter((item) => item !== null);
}

import { Download, FileCode } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";
import { Forbidden } from "@/components/common/forbidden";
import { PageHeader } from "@/components/common/page-header";
import { CopyButton } from "@/components/scripts/copy-button";
import { getMembershipWithRole } from "@/lib/auth/require-role";
import { formatBytes } from "@/lib/format";
import { listScriptPackages } from "@/lib/scripts/catalog";

export const metadata: Metadata = { title: "스크립트 센터" };

const DESCRIPTION =
  "OS별 표준 점검 스크립트를 내려받아 대상 서버에서 실행하고, 결과 파일을 신규 진단 화면에 업로드합니다.";

function CommandLine({ label, command }: { label: string; command: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-caption text-muted-foreground">{label}</span>
      <div className="flex items-center gap-2">
        <code className="min-w-0 flex-1 overflow-x-auto rounded-md bg-background px-3 py-2 font-mono text-caption whitespace-nowrap">
          {command}
        </code>
        <CopyButton value={command} label={label} />
      </div>
    </div>
  );
}

export default async function ScriptsPage() {
  const membership = await getMembershipWithRole(["owner", "operator"]);
  if (!membership) {
    return (
      <>
        <PageHeader title="표준 진단 스크립트 센터" description={DESCRIPTION} />
        <Forbidden description="스크립트 센터는 워크스페이스 소유자 또는 작업자만 사용할 수 있습니다." />
      </>
    );
  }

  const packages = await listScriptPackages();

  return (
    <>
      <PageHeader title="표준 진단 스크립트 센터" description={DESCRIPTION} />
      {packages.length === 0 ? (
        <EmptyState
          icon={FileCode}
          title="제공되는 공식 스크립트가 없습니다"
          description="관리자에게 문의하세요."
        />
      ) : (
        <div className="flex flex-col gap-6">
          <div className="grid gap-4 xl:grid-cols-2">
            {packages.map((pkg) => (
              <section
                key={pkg.os}
                aria-labelledby={`script-${pkg.os}`}
                className="flex min-w-0 flex-col gap-4 rounded-md border border-border bg-card p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex min-w-0 flex-col gap-1">
                    <h2 id={`script-${pkg.os}`} className="text-h3">
                      {pkg.title}
                    </h2>
                    <p className="text-caption text-muted-foreground">
                      {pkg.supported} · 버전 {pkg.version} ·{" "}
                      {formatBytes(pkg.sizeBytes)}
                    </p>
                  </div>
                  <a href={pkg.href} download className={buttonStyles.primary}>
                    <Download aria-hidden="true" className="size-4" />
                    {pkg.fileName} 다운로드
                  </a>
                </div>
                <CommandLine label="SHA-256 체크섬" command={pkg.sha256} />
                {pkg.steps.map((step) => (
                  <CommandLine
                    key={step.label}
                    label={step.label}
                    command={step.command}
                  />
                ))}
              </section>
            ))}
          </div>

          <section
            aria-labelledby="guide-title"
            className="flex flex-col gap-2"
          >
            <h2 id="guide-title" className="text-h3">
              실행 안내
            </h2>
            <ol className="flex list-decimal flex-col gap-1 pl-5 text-body text-muted-foreground">
              <li>내려받은 파일의 체크섬이 위 값과 같은지 먼저 확인하세요.</li>
              <li>
                스크립트는 설정을 바꾸지 않고 점검 근거만 수집합니다. 비밀번호
                해시 등 비밀 값은 모으지 않습니다.
              </li>
              <li>
                실행한 폴더에 &lt;호스트명&gt;_&lt;OS&gt;_&lt;일시&gt;.txt 결과
                파일이 만들어집니다.
              </li>
              <li>
                여러 서버의 결과는 하나의 .zip 으로 묶어{" "}
                <Link
                  href="/assessments/new"
                  className="text-primary underline underline-offset-4"
                >
                  신규 진단
                </Link>{" "}
                화면에 한 번에 올릴 수 있습니다(최대 50MB).
              </li>
            </ol>
          </section>
        </div>
      )}
    </>
  );
}

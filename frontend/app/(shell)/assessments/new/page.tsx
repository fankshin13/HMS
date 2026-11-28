import type { Metadata } from "next";
import Link from "next/link";
import { Forbidden } from "@/components/common/forbidden";
import { PageHeader } from "@/components/common/page-header";
import { UploadForm } from "@/components/upload/upload-form";
import { getMembershipWithRole } from "@/lib/auth/require-role";
import { seoulToday } from "@/lib/format";

export const metadata: Metadata = { title: "신규 진단" };

const DESCRIPTION =
  "점검 스크립트 실행 결과를 업로드하면 호스트와 OS 정보를 자동으로 확인합니다.";

export default async function NewAssessmentPage() {
  const membership = await getMembershipWithRole(["owner", "operator"]);

  return (
    <>
      <PageHeader title="신규 진단 차수 시작" description={DESCRIPTION} />
      {membership ? (
        <>
          <p className="mb-4 text-body text-muted-foreground">
            아직 결과 파일이 없다면{" "}
            <Link
              href="/scripts"
              className="text-primary underline underline-offset-4"
            >
              스크립트 센터
            </Link>
            에서 표준 점검 스크립트를 내려받아 대상 서버에서 실행하세요.
          </p>
          <UploadForm defaultTitle={`${seoulToday()} 인프라 정기 진단`} />
        </>
      ) : (
        <Forbidden description="진단 파일 업로드는 워크스페이스 소유자 또는 작업자만 할 수 있습니다." />
      )}
    </>
  );
}

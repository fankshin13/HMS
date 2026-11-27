import { FileCode } from "lucide-react";
import type { Metadata } from "next";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";

export const metadata: Metadata = { title: "스크립트 센터" };

export default function ScriptsPage() {
  return (
    <>
      <PageHeader
        title="표준 진단 스크립트 센터"
        description="OS별(Linux, Windows Server) 표준 점검 스크립트를 내려받아 대상 서버에서 실행합니다."
      />
      <EmptyState
        icon={FileCode}
        title="사용 가능한 표준 진단 스크립트가 없습니다"
        description="스크립트 패키지가 등록되면 이곳에서 OS별로 내려받을 수 있습니다."
      />
    </>
  );
}

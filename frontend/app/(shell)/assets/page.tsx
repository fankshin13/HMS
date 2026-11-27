import { Server } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";
import { PageHeader } from "@/components/common/page-header";

export const metadata: Metadata = { title: "자산 목록" };

export default function AssetsPage() {
  return (
    <>
      <PageHeader
        title="자산 목록"
        description="진단 대상 서버와 자산 중요도(기밀성·완전성·가용성)를 관리합니다."
        actions={
          <Link href="/scripts" className={buttonStyles.secondary}>
            자산 등록 방법 안내
          </Link>
        }
      />
      <EmptyState
        icon={Server}
        title="등록된 진단 대상 자산이 없습니다"
        description="진단 스크립트를 실행하고 결과 파일을 업로드하면 자산이 자동 등록됩니다."
        action={
          <Link href="/assessments/new" className={buttonStyles.primary}>
            결과 파일 업로드하기
          </Link>
        }
      />
    </>
  );
}

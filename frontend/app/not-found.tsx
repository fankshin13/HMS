import { SearchX } from "lucide-react";
import Link from "next/link";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";

export default function NotFound() {
  return (
    <main className="flex min-h-dvh items-center justify-center p-4">
      <EmptyState
        icon={SearchX}
        title="페이지를 찾을 수 없습니다"
        description="주소가 잘못되었거나 접근할 수 없는 항목입니다."
        action={
          <Link href="/dashboard" className={buttonStyles.primary}>
            대시보드로 이동
          </Link>
        }
      />
    </main>
  );
}

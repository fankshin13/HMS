"use client";

import { TriangleAlert } from "lucide-react";
import { useEffect } from "react";
import { buttonStyles } from "@/components/common/button-styles";
import { EmptyState } from "@/components/common/empty-state";

export default function ShellError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("화면 렌더링 실패", error.digest ?? error.message);
  }, [error]);

  return (
    <div role="alert">
      <EmptyState
        icon={TriangleAlert}
        title="화면을 불러오지 못했습니다"
        description="잠시 후 다시 시도해 주세요. 문제가 계속되면 관리자에게 알려 주세요."
        action={
          <button
            type="button"
            className={buttonStyles.secondary}
            onClick={reset}
          >
            다시 시도
          </button>
        }
      />
    </div>
  );
}

import { useId, type ReactNode } from "react";
import { buttonStyles } from "./button-styles";

// 이후 태스크에서 구현될 동작 버튼. 지금은 비활성 상태로 두고 이유를 함께 알린다.
export function PendingFeatureButton({ children }: { children: ReactNode }) {
  const noteId = useId();
  return (
    <span className="flex flex-col items-center gap-1 sm:items-end">
      <button
        type="button"
        disabled
        aria-describedby={noteId}
        className={buttonStyles.primary}
      >
        {children}
      </button>
      <span id={noteId} className="text-caption text-muted-foreground">
        준비 중인 기능입니다
      </span>
    </span>
  );
}

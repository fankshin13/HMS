import { CircleAlert } from "lucide-react";
import type { ReactNode } from "react";

/** 오류 안내. 색만으로 구분하지 않도록 아이콘과 문구를 함께 쓴다. */
export function ErrorAlert({ children }: { children: ReactNode }) {
  return (
    <p
      role="alert"
      className="flex items-start gap-2 rounded-md border border-status-danger bg-background px-3 py-2 text-left text-body"
    >
      <CircleAlert
        aria-hidden="true"
        className="mt-0.5 size-4 shrink-0 text-status-danger"
      />
      <span>{children}</span>
    </p>
  );
}

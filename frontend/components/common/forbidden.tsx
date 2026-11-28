import { ShieldX } from "lucide-react";
import { EmptyState } from "./empty-state";

export function Forbidden({ description }: { description: string }) {
  return (
    <EmptyState
      icon={ShieldX}
      title="접근 권한이 없습니다"
      description={description}
    />
  );
}

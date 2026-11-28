import { ShieldCheck } from "lucide-react";
import Link from "next/link";

export function Brand() {
  return (
    <Link
      href="/dashboard"
      className="flex min-h-11 items-center gap-2 rounded-md px-3 text-h3 font-semibold"
    >
      <ShieldCheck aria-hidden="true" className="size-5 text-primary" />
      취약점 진단
    </Link>
  );
}

export function WorkspaceBadge({ name }: { name: string | null }) {
  return (
    <div className="mx-3 rounded-md border border-border px-3 py-2">
      <p className="text-caption text-muted-foreground">워크스페이스</p>
      <p className="text-body font-medium">{name ?? "소속 없음"}</p>
    </div>
  );
}

"use client";

import { ChevronRight, CircleUserRound, LogOut } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut } from "@/app/auth/verify/actions";
import { MobileDrawer } from "./mobile-drawer";
import { getBreadcrumbs } from "./navigation";

export function Header({
  account,
  workspaceName,
}: {
  account: { name: string; email: string } | null;
  workspaceName: string | null;
}) {
  const crumbs = getBreadcrumbs(usePathname());

  return (
    <header className="sticky top-0 z-10 flex min-h-14 items-center gap-2 border-b border-border bg-background px-2 sm:px-4">
      <MobileDrawer workspaceName={workspaceName} />
      <nav aria-label="현재 위치" className="min-w-0 flex-1">
        <ol className="flex min-w-0 items-center gap-1 text-body">
          {crumbs.map((crumb, index) => (
            <li
              key={`${crumb.label}-${index}`}
              className="flex min-w-0 items-center gap-1"
            >
              {index > 0 && (
                <ChevronRight
                  aria-hidden="true"
                  className="size-4 shrink-0 text-muted-foreground"
                />
              )}
              {crumb.href ? (
                <Link
                  href={crumb.href}
                  className="inline-flex min-h-11 min-w-0 items-center truncate text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
                >
                  {crumb.label}
                </Link>
              ) : (
                <span
                  aria-current={
                    index === crumbs.length - 1 ? "page" : undefined
                  }
                  className={`truncate ${index === crumbs.length - 1 ? "font-semibold" : "text-muted-foreground"}`}
                >
                  {crumb.label}
                </span>
              )}
            </li>
          ))}
        </ol>
      </nav>
      <p className="hidden text-caption text-muted-foreground md:block">
        기준 시간대 Asia/Seoul
      </p>
      <p className="flex min-w-0 shrink-0 items-center gap-2 text-caption text-muted-foreground">
        <CircleUserRound aria-hidden="true" className="size-5 shrink-0" />
        <span
          className="sr-only max-w-40 truncate sm:not-sr-only"
          title={account?.email}
        >
          {account ? account.name : "소속 없음"}
        </span>
      </p>
      <form action={signOut}>
        <button
          type="submit"
          aria-label="로그아웃"
          className="inline-flex size-11 items-center justify-center rounded-md text-muted-foreground hover:bg-card hover:text-foreground"
        >
          <LogOut aria-hidden="true" className="size-5" />
        </button>
      </form>
    </header>
  );
}

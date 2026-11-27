"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { NAVIGATION, isActivePath } from "./navigation";

export function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();

  return (
    <nav aria-label="주 메뉴" className="flex flex-col gap-6">
      {NAVIGATION.map((group) => (
        <div key={group.label} className="flex flex-col gap-1">
          <p className="px-3 text-caption font-medium text-muted-foreground">
            {group.label}
          </p>
          <ul className="flex flex-col gap-1">
            {group.items.map((item) => {
              const active = isActivePath(pathname, item);
              const Icon = item.icon;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    onClick={onNavigate}
                    aria-current={active ? "page" : undefined}
                    className={`relative flex min-h-11 items-center gap-3 rounded-md px-3 text-body transition-colors ${
                      active
                        ? "bg-primary/15 font-semibold text-foreground before:absolute before:inset-y-2 before:left-0 before:w-1 before:rounded-md before:bg-primary"
                        : "text-muted-foreground hover:bg-card hover:text-foreground"
                    }`}
                  >
                    <Icon aria-hidden="true" className="size-4 shrink-0" />
                    {item.title}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

import { Brand, WorkspaceBadge } from "./brand";
import { NavList } from "./nav-list";

export function Sidebar() {
  return (
    <aside className="fixed inset-y-0 left-0 hidden w-64 flex-col gap-4 overflow-y-auto border-r border-border bg-background p-3 lg:flex">
      <Brand />
      <WorkspaceBadge />
      <NavList />
    </aside>
  );
}

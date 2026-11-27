import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
}: EmptyStateProps) {
  return (
    <section className="flex flex-col items-center gap-3 rounded-md border border-dashed border-border bg-card px-4 py-12 text-center">
      <Icon aria-hidden="true" className="size-8 text-muted-foreground" />
      <h2 className="text-h3">{title}</h2>
      {description && (
        <p className="max-w-prose text-body text-muted-foreground">
          {description}
        </p>
      )}
      {action && (
        <div className="mt-2 flex flex-wrap justify-center gap-2">{action}</div>
      )}
    </section>
  );
}

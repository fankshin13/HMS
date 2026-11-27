const base =
  "inline-flex min-h-11 items-center justify-center gap-2 rounded-md px-4 text-body font-medium transition-colors disabled:cursor-not-allowed";

export const buttonStyles = {
  primary: `${base} bg-primary-action text-primary-foreground hover:bg-primary-action/90 disabled:border disabled:border-dashed disabled:border-muted-foreground disabled:bg-transparent disabled:text-muted-foreground`,
  secondary: `${base} border border-border bg-card text-foreground hover:bg-border disabled:text-muted-foreground`,
};

const bar = "rounded-md bg-card motion-safe:animate-pulse";

export function LoadingSkeleton({
  type,
}: {
  type: "table" | "cards" | "detail";
}) {
  return (
    <div role="status" aria-live="polite" className="flex flex-col gap-4">
      <span className="sr-only">불러오는 중입니다</span>
      <div className={`${bar} h-8 w-48`} />
      {type === "cards" && (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }, (_, i) => (
            <div key={i} className={`${bar} h-24`} />
          ))}
        </div>
      )}
      {type === "table" && (
        <div className="flex flex-col gap-2">
          <div className={`${bar} h-10`} />
          {Array.from({ length: 5 }, (_, i) => (
            <div key={i} className={`${bar} h-8 opacity-70`} />
          ))}
        </div>
      )}
      {type === "detail" && (
        <>
          <div className={`${bar} h-32`} />
          <div className={`${bar} h-64`} />
        </>
      )}
    </div>
  );
}

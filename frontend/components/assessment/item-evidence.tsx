import { splitSnippet } from "@/lib/assessments/item-filters";

/** 판정 근거, KISA 양호/취약 기준, 조치 방법, 스크립트 원문 */
export function ItemEvidence({
  snippet,
  startLine,
  endLine,
  guide,
}: {
  snippet: string | null;
  startLine: number | null;
  endLine: number | null;
  guide: {
    good_condition: string;
    vulnerable_condition: string;
    remediation_guide: string;
  };
}) {
  const { reason, evidence } = splitSnippet(snippet);
  return (
    <div className="flex flex-col gap-3 text-body">
      {reason && (
        <p>
          <span className="font-medium">판정 근거</span> {reason}
        </p>
      )}
      <dl className="grid gap-1 sm:grid-cols-[6rem_1fr]">
        <dt className="text-muted-foreground">양호 기준</dt>
        <dd>{guide.good_condition}</dd>
        <dt className="text-muted-foreground">취약 기준</dt>
        <dd>{guide.vulnerable_condition}</dd>
        <dt className="text-muted-foreground">조치 방법</dt>
        <dd>{guide.remediation_guide}</dd>
      </dl>
      {evidence && (
        <div className="flex flex-col gap-1">
          <span className="text-caption text-muted-foreground">
            스크립트 출력 원문 ({startLine}–{endLine}번째 줄)
          </span>
          <pre className="max-h-64 overflow-auto rounded-md bg-background p-3 font-mono text-caption whitespace-pre">
            {evidence}
          </pre>
        </div>
      )}
    </div>
  );
}

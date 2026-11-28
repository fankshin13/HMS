"use client";

import { LoaderCircle } from "lucide-react";
import { useActionState, useState } from "react";
import {
  type PolicyState,
  saveRiskPolicy,
} from "@/app/(shell)/settings/risk-policy/actions";
import { buttonStyles } from "@/components/common/button-styles";
import { inputStyles, labelStyles } from "@/components/common/form-styles";

const initial: PolicyState = { status: "idle", message: "" };

export type PolicyValues = {
  confidentialityWeight: number;
  integrityWeight: number;
  availabilityWeight: number;
  criticalThreshold: number;
  warningThreshold: number;
};

/** 위험도 정책 편집. 입력하는 동안 대표 점수 예시를 바로 보여 준다. */
export function RiskPolicyForm({ values }: { values: PolicyValues }) {
  const [state, action, pending] = useActionState(saveRiskPolicy, initial);
  const [draft, setDraft] = useState(values);
  const set =
    (key: keyof PolicyValues) => (event: React.ChangeEvent<HTMLInputElement>) =>
      setDraft({ ...draft, [key]: Number(event.target.value) });
  const maxImportance =
    3 *
    (draft.confidentialityWeight +
      draft.integrityWeight +
      draft.availabilityWeight);
  const example = (importance: number, weight: number) =>
    (importance * weight).toFixed(2);

  const weightFields: {
    key: keyof PolicyValues;
    name: string;
    label: string;
  }[] = [
    {
      key: "confidentialityWeight",
      name: "confidentialityWeight",
      label: "기밀성 가중치",
    },
    { key: "integrityWeight", name: "integrityWeight", label: "무결성 가중치" },
    {
      key: "availabilityWeight",
      name: "availabilityWeight",
      label: "가용성 가중치",
    },
  ];
  return (
    <form action={action} className="flex max-w-2xl flex-col gap-5">
      <fieldset className="flex flex-col gap-3">
        <legend className="mb-2 text-h3">자산 중요도 가중치 (0.5 ~ 3.0)</legend>
        <div className="grid gap-3 sm:grid-cols-3">
          {weightFields.map((f) => (
            <label key={f.key} className="flex flex-col gap-1">
              <span className={labelStyles}>{f.label}</span>
              <input
                type="number"
                name={f.name}
                min={0.5}
                max={3}
                step={0.05}
                required
                value={draft[f.key]}
                onChange={set(f.key)}
                className={inputStyles}
              />
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset className="flex flex-col gap-3">
        <legend className="mb-2 text-h3">위험 등급 기준 점수</legend>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="flex flex-col gap-1">
            <span className={labelStyles}>긴급 (이상, 7일 이내 조치)</span>
            <input
              type="number"
              name="criticalThreshold"
              min={2}
              max={81}
              step={1}
              required
              value={draft.criticalThreshold}
              onChange={set("criticalThreshold")}
              className={inputStyles}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className={labelStyles}>경고 (이상, 30일 이내 조치)</span>
            <input
              type="number"
              name="warningThreshold"
              min={1}
              max={80}
              step={1}
              required
              value={draft.warningThreshold}
              onChange={set("warningThreshold")}
              className={inputStyles}
            />
          </label>
        </div>
        <p className="text-caption text-muted-foreground">
          경고 기준 미만은 주의(90일 이내)입니다.
        </p>
      </fieldset>
      <div className="rounded-md border border-border bg-card p-3 text-body">
        <p className="font-medium">점수 예시</p>
        <p className="text-muted-foreground">
          위험 점수 = (기밀성×{draft.confidentialityWeight} + 무결성×
          {draft.integrityWeight} + 가용성×{draft.availabilityWeight}) × 취약
          등급(상 3·중 2·하 1)
        </p>
        <p className="text-muted-foreground">
          최고 중요도 자산(3·3·3)의 {"'상'"} 항목: {example(maxImportance, 3)}점
          · 보통 자산(2·2·2)의 {"'상'"} 항목:{" "}
          {example(
            2 *
              (draft.confidentialityWeight +
                draft.integrityWeight +
                draft.availabilityWeight),
            3,
          )}
          점
        </p>
      </div>
      <div className="flex flex-col items-start gap-2">
        <button
          type="submit"
          className={buttonStyles.primary}
          disabled={pending}
        >
          {pending && (
            <LoaderCircle
              aria-hidden="true"
              className="size-4 motion-safe:animate-spin"
            />
          )}
          정책 저장 및 점수 재계산
        </button>
        <p
          role="status"
          aria-live="polite"
          className={`text-body ${state.status === "error" ? "text-status-danger" : "text-status-safe"}`}
        >
          {state.message}
        </p>
      </div>
    </form>
  );
}

# 시스템 취약점 진단 Project

진단 스크립트 로그 업로드 한 번으로 3종 보고서(상세·요약·위험평가)를 자동 생성하는 B2B SaaS.

## 구조
- `frontend/` — Next.js (App Router), TypeScript strict, ESLint, Prettier, Vitest
- `backend/` — Python 3.11+, FastAPI, Ruff, mypy(strict), Pytest

## 준비
- Node.js 22+, pnpm 10 (`corepack enable`)
- [uv](https://docs.astral.sh/uv/) (Python 의존성 관리, 잠금 파일 `backend/uv.lock`)

```bash
pnpm install
uv sync --project backend
```

## 검사 (루트에서 실행)
| 명령 | 내용 |
| --- | --- |
| `pnpm typecheck` | tsc --noEmit + mypy |
| `pnpm lint` | ESLint + Prettier 검사 + Ruff lint/format 검사 |
| `pnpm test` | Vitest + Pytest |
| `pnpm build` | next build |
| `pnpm check` | 위 4개 일괄 |

## 환경 변수
`.env.example`에 이름만 정리돼 있습니다. 값은 `.env`(커밋 금지) 또는 서버 측 시크릿 저장소에 둡니다.

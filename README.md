# 시스템 취약점 진단 Project

진단 스크립트 로그 업로드 한 번으로 3종 보고서(상세·요약·위험평가)를 자동 생성하는 B2B SaaS.

## 구조
- `frontend/` — Next.js (App Router), TypeScript strict, ESLint, Prettier, Vitest
- `backend/` — Python 3.11+, FastAPI, Pydantic 모델(`backend/models`), Ruff, mypy(strict), Pytest
- `supabase/` — Supabase CLI 설정과 마이그레이션(스키마·RLS·KISA 기준 시드)

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

## 데이터베이스 (Supabase)
- 스키마 변경은 `supabase/migrations/` 에 새 마이그레이션으로만 기록합니다 (`pnpm exec supabase migration new <이름>`). 적용된 마이그레이션은 수정하지 않습니다.
- 테넌트 격리는 RLS(행 단위 보안)로 강제합니다. 접근 모델은 `supabase/migrations/*_core_schema.sql` 상단 주석 참고.
- 판정 수동 변경은 `public.apply_item_override(result_id, new_status, reason)` 으로만 가능하며, 감사 로그(`override_audit_logs`)는 수정·삭제가 차단됩니다.

### 로컬 DB 테스트
DB 테스트는 로컬 PostgreSQL 15+ 에 일회용 데이터베이스를 만들어 마이그레이션과 역할별 접근(anon / authenticated / service_role)을 검증하고, 끝나면 삭제합니다. `TEST_DATABASE_URL` 이 없으면 건너뜁니다(로컬 호스트만 허용).

```bash
TEST_DATABASE_URL=postgresql://<user>:<password>@localhost:5432/postgres pnpm backend:test
```

### DB 타입 생성
마이그레이션을 적용한 로컬 DB 를 가리키는 `LOCAL_DATABASE_URL` 로 `pnpm db:types` 를 실행하면 `frontend/lib/database.types.ts` 가 갱신됩니다.

## 환경 변수
`.env.example`에 이름만 정리돼 있습니다. 값은 `.env`(커밋 금지) 또는 서버 측 시크릿 저장소에 둡니다.

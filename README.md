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

## 로그인과 초대 (Supabase Auth 매직 링크)
1. **첫 소유자 만들기**: `backend` 에서 실행하면 워크스페이스·소유자 계정과 소유자용 1회용 초대 링크(24시간)가 출력됩니다.
   ```bash
   DATABASE_URL=... INVITATION_TOKEN_SALT=... APP_URL=https://... uv run python -m scripts.provision_owner --tenant-name "보안팀" --owner-name "홍길동" --owner-email owner@example.com
   ```
2. **팀원 초대**: 소유자가 `/settings/team` 에서 이름·이메일·역할·유효기간(1~72시간)으로 링크를 만들고, 사내 메신저 등으로 직접 전달합니다. 미사용 링크는 철회할 수 있습니다.
3. **참여**: 초대받은 사람이 링크를 열고 "참여"를 누르면 초대받은 이메일로 매직 링크가 발송됩니다. **같은 브라우저**에서 메일 링크를 열면 `/auth/callback` 이 세션을 만들고 초대를 수락합니다(1회용, 만료·철회·다른 이메일 계정은 거부).
4. **재로그인**: `/auth/verify` 에서 이메일을 입력하면 기존 계정에만 매직 링크가 발송됩니다.

Supabase 프로젝트 설정: Authentication → URL Configuration 의 Redirect URLs 에 `<APP_URL>/auth/callback` 을 추가하세요. 기본 메일 발송은 시간당 발송량 제한이 있으므로 운영 전 SMTP 를 설정해야 합니다.

## 환경 변수
`.env.example`에 이름만 정리돼 있습니다. 값은 `.env`(커밋 금지) 또는 서버 측 시크릿 저장소에 둡니다.

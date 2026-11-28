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

## 점검 스크립트와 업로드
- 표준 점검 스크립트: `frontend/public/scripts/` (`kisa_check_linux.sh`, `kisa_check_windows.bat`). 읽기 전용으로 근거만 수집하며, 결과 파일 첫 줄은 `[START] OS=<Linux|Windows> HOSTNAME=<호스트명> ...`, 항목은 `==== <항목> BEGIN/END ====`, 마지막 줄은 `[END]` 형식입니다. 스크립트를 바꾸면 `SCRIPT_VERSION` 을 올리세요. 스크립트 센터(`/scripts`)의 체크섬은 파일에서 자동 계산됩니다.
- Windows 배치 파일은 코드 페이지 문제를 피하려고 ASCII·CRLF 로만 작성합니다.
- 업로드(`/assessments/new`): 브라우저 작업 스레드에서 압축 해제 → 사설 IP(RFC 1918)·개인 계정명을 가명(`MASKED_IP_001`, `MASKED_USER_001`)으로 치환 → 머리말 검사 후 전송합니다. 원본↔가명 대응표는 브라우저 밖으로 나가지 않습니다. 서버(`/api/assessments/upload`)는 다시 검사한 뒤 로그를 비공개 버킷 `diagnostic-raw/<tenant>/<run>/` 에 저장하고 `register_assessment_upload` 로 진단 차수·자산·로그를 등록합니다. 형식이 깨진 파일은 `partial_error` 로 격리되고 나머지는 정상 처리됩니다.
- 제한: 업로드 50MB, 압축 해제 총량 200MB, 로그 파일 500개. 같은 파일을 10분 안에 다시 올리면 확인을 받습니다.

## 자동 판정 엔진 (backend/modules)
- `modules/parser/log_parser.py`: 표준 스크립트 결과를 구간 단위로 나누는 순수 파서. 어떤 입력에도 예외를 던지지 않고, 해석할 수 없는 줄은 줄 번호와 함께 오류 목록에 담습니다.
- 기준: KISA 「2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」. Unix 67개·Windows 64개 항목의 기준표(이름·중요도·판단 기준·조치 방법)는 원문에서 추출해 `compliance_guidelines` 에 적재했습니다.
- `modules/compliance/`: 자동 판정 규칙. Unix 41개(중요도 '상' 40개 전부 + U-66), Windows 32개(중요도 '상' 31개 전부 + W-05)를 판정합니다. Unix: `kisa_linux.py`(v1.1 항목), `kisa_linux_files.py`·`kisa_linux_services.py`(v1.2 추가), Windows: `kisa_windows.py`, `kisa_windows_high.py`. 구간 안에 `RESULT=OK|VULNERABLE|N/A` 가 있으면 우선합니다. 근거가 부족하면 보수적으로 '취약'으로 판정하고 사유를 남깁니다. 업무상 필요 여부처럼 자동으로 알 수 없는 부분은 객관적 기준(90일 미접속, 패치 60일, 백신 서명 7일 등)으로 판정하며, 예외는 사유와 함께 판정을 변경합니다.
- 규칙마다 근거를 수집하기 시작한 스크립트 버전(`since`)이 있어, 예전 버전 스크립트 결과는 수집된 항목만 판정하고 오류로 격리하지 않습니다. 스크립트 버전: Linux 1.2.0, Windows 1.1.0.
- 비밀 값은 수집하지 않습니다(SNMP 커뮤니티 문자열·v3 비밀번호는 스크립트에서 가림). 업로더는 사설 IP와 계정명(`USER=`·`OWNER=`·`GROUP=`·`/home/<이름>`·`ADMIN_MEMBER=`)을 같은 가명으로 일관되게 치환해 소유자 비교 판정이 유지됩니다.
- `modules/worker/`: `queued` 진단 차수를 선점해 `parsing → scoring → completed` 로 처리합니다(멱등, 로그 단위 커밋, 저장소 장애 시 `failed`). 형식이 깨진 로그는 `partial_error` 로 격리하고, 판정 가능한 항목은 저장합니다.
- 실행: `cd backend && uv run python -m modules.worker` (대기열이 빌 때까지만 처리하려면 `--once`). 필요한 환경 변수는 `backend/.env.example` 참고.

## 위험평가와 판정 변경
- 위험 점수 = 자산 중요도(기밀성×W_c + 무결성×W_i + 가용성×W_a, 각 1~3점·가중치 기본 1.00 → 3~9) × 취약 등급(상 3·중 2·하 1). '취약'이 아니면 0점입니다.
- 등급: 긴급 ≥ 15, 경고 ≥ 8, 그 외 주의(테넌트별 `risk_scoring_policies` 로 변경 가능).
- 같은 공식이 `private.compute_risk_score`(SQL)와 `modules/compliance/risk_evaluator.py`(Python)에 있고, `tests/db/test_risk.py` 가 모든 조합에서 두 결과가 같은지 확인합니다. 워커는 판정 후 점수를 계산하고 진단 차수를 `completed` 로 바꿉니다.
- 점검 항목 화면(`/assessments/<id>/items`): 위험 점수 높은 순 목록, 위험 요약, 판정 변경(owner·operator, 사유 5~1000자), 변경 이력. 변경은 `public.apply_item_override` 한 번의 트랜잭션으로 점수 재산정·감사 기록(수정·삭제 불가)·취약 건수 동기화를 처리합니다.
- API: `POST /api/assessments/<id>/items/<itemId>/override`, `GET /api/assessments/<id>/items/<itemId>/audits`.

## 환경 변수
`.env.example`에 이름만 정리돼 있습니다. 값은 `.env`(커밋 금지) 또는 서버 측 시크릿 저장소에 둡니다.

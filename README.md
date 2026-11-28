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
- `modules/compliance/`: 자동 판정 규칙. KISA 2026 기준 Unix 67개·Windows 64개 **전 항목(131개)** 을 판정합니다. Unix: `kisa_linux.py`(v1.1 항목), `kisa_linux_files.py`·`kisa_linux_services.py`(v1.2, 중요도 '상'), `kisa_linux_medium.py`(v1.3, '중'·'하'), Windows: `kisa_windows.py`, `kisa_windows_high.py`('상'), `kisa_windows_medium.py`('중'·'하'). 구간 안에 `RESULT=OK|VULNERABLE|N/A` 가 있으면 우선합니다. 근거가 부족하면 보수적으로 '취약'으로 판정하고 사유를 남깁니다. 업무상 필요 여부처럼 자동으로 알 수 없는 부분은 객관적 기준(90일 미접속, 패치 60일, 백신 서명 7일 등)으로 판정하고, 정기 검토가 기준인 항목(숨김 파일·예약 작업·시작 프로그램·ODBC 등)은 목록을 보여 주며 '취약(검토 필요)'으로 판정합니다. 예외는 판정 변경(사유 기록)으로 처리합니다.
- 규칙마다 근거를 수집하기 시작한 스크립트 버전(`since`)이 있어, 예전 버전 스크립트 결과는 수집된 항목만 판정하고 오류로 격리하지 않습니다. 스크립트 버전: Linux 1.3.0, Windows 1.2.0.
- 비밀 값은 수집하지 않습니다(SNMP 커뮤니티 문자열·v3 비밀번호는 스크립트에서 가리고 기본값 여부·복잡도만 남김, 비밀번호 해시는 알고리즘별 개수만 수집). 업로더는 사설 IP와 계정명(`USER=`·`ACCOUNT=`·`OWNER=`·`GROUP=`·`/home/<이름>`·`ADMIN_MEMBER=`·`RDP_MEMBER=`·`C:\Users\<이름>`)을 같은 가명으로 일관되게 치환해 소유자 비교 판정이 유지됩니다.
- `modules/worker/`: `queued` 진단 차수를 선점해 `parsing → scoring → completed` 로 처리합니다(멱등, 로그 단위 커밋, 저장소 장애 시 `failed`). 형식이 깨진 로그는 `partial_error` 로 격리하고, 판정 가능한 항목은 저장합니다.
- 실행: `cd backend && uv run python -m modules.worker` (대기열이 빌 때까지만 처리하려면 `--once`). 필요한 환경 변수는 `backend/.env.example` 참고.

## 위험평가와 판정 변경
- 위험 점수 = 자산 중요도(기밀성×W_c + 무결성×W_i + 가용성×W_a, 각 1~3점·가중치 기본 1.00 → 3~9) × 취약 등급(상 3·중 2·하 1). '취약'이 아니면 0점입니다.
- 등급: 긴급 ≥ 15, 경고 ≥ 8, 그 외 주의(테넌트별 `risk_scoring_policies` 로 변경 가능).
- 같은 공식이 `private.compute_risk_score`(SQL)와 `modules/compliance/risk_evaluator.py`(Python)에 있고, `tests/db/test_risk.py` 가 모든 조합에서 두 결과가 같은지 확인합니다. 워커는 판정 후 점수를 계산하고 진단 차수를 `completed` 로 바꿉니다.
- 점검 항목 화면(`/assessments/<id>/items`): 위험 점수 높은 순 목록, 위험 요약, 판정 변경(owner·operator, 사유 5~1000자), 변경 이력. 변경은 `public.apply_item_override` 한 번의 트랜잭션으로 점수 재산정·감사 기록(수정·삭제 불가)·취약 건수 동기화를 처리합니다.
- API: `POST /api/assessments/<id>/items/<itemId>/override`, `GET /api/assessments/<id>/items/<itemId>/audits`.

## 3종 보고서 (backend/modules/renderer, /assessments/<id>/reports)
- 한 번의 요청으로 「취약점 진단 상세 결과 보고서」, 「취약점 진단 결과 보고서」(경영진·관리자용 요약), 「위험평가 결과 및 조치계획서」를 DOCX·PDF 로 함께 만듭니다(6개 파일). 일부만 만들지 않습니다.
- 구조: 워커가 DB 에서 결과를 읽어 `ReportData`(DTO)를 만들고 → `reports.py` 가 보고서별 중립 문서 블록을 구성 → `docx_builder.py`(python-docx)와 `pdf_builder.py`(WeasyPrint)가 같은 블록을 각각 그립니다. 조판 코어는 DB 를 직접 조회하지 않습니다.
- 표 서식: DOCX 의 모든 표 행에 `cantSplit`, 머리글 행에 `tblHeader`(페이지마다 반복)·`keep_with_next`. PDF 는 행 분할 방지·머리글 반복.
- 위험평가서 부록 A 에 수동 판정 변경 감사 이력(일시·호스트·항목·변경 전후·사유·변경자)을 싣습니다.
- 대기열: `report_jobs`(queued → rendering → completed/failed). 진단 차수 상태와 분리되어, 조판이 실패해도 분석 결과는 그대로이며 재시도할 수 있습니다. 15분 넘게 멈춘 조판은 다시 선점합니다. 3종을 프로세스 3개로 동시에 조판합니다(50대 기준 약 40~50초).
- 저장: 비공개 버킷 `reports/<tenant>/<run>/<type>.<format>`(쓰기는 워커만, 읽기는 테넌트 구성원). 보존 기한 24시간이 지나면 워커가 삭제합니다.
- 제로 리텐션: 테넌트 설정이 켜져 있으면 owner·operator 가 ZIP 일괄 다운로드를 마친 뒤 확인을 거쳐 원본 로그를 영구 삭제합니다(`purge_raw_diagnostic_data`, 감사 기록 `purge_audit_logs`). 내려받지 않아도 보고서 생성 24시간 뒤 워커가 자동 파기합니다. 판정 결과와 보고서는 남습니다.
- API: `POST /api/assessments/<id>/reports/generate[?force=true]`, `GET /api/assessments/<id>/reports`, `GET .../reports/<detailed|summary|risk_plan>/download?format=docx|pdf`, `GET .../reports/bundle/download`, `POST .../reports/purge-raw`.
- 워커 실행 환경: pango·cairo·harfbuzz(가능하면 libharfbuzz-subset) 시스템 라이브러리, 한글 글꼴. `REPORT_FONT_DIR` 에 Pretendard-Regular.otf·Pretendard-Bold.otf 를 두면 PDF·차트에 사용하고, 없으면 시스템 한글 글꼴(Noto Sans CJK KR 등)을 씁니다. DOCX 는 '맑은 고딕'으로 표시됩니다.

## Supabase 프로젝트
- 원격 프로젝트 「시스템 취약점 진단 Project」(ref `ghcpajruzahivwewpktx`, ap-northeast-1)에 `supabase/migrations` 전체를 적용했습니다. 보안 점검(advisor)은 ERROR 없음(경고는 내부에서 로그인·역할을 확인하는 의도된 SECURITY DEFINER 함수), 성능 점검의 외래키 인덱스 안내는 `20261128060000_foreign_key_indexes.sql` 로 해소했습니다.
- 배포 전 대시보드에서 할 일: Auth 사이트 URL·리디렉션 URL(`<APP_URL>/auth/callback`) 등록, 이메일(매직 링크) 발신 설정, 앱 환경 변수(`NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`)와 워커 시크릿(`SUPABASE_SERVICE_ROLE_KEY`, `DATABASE_URL`) 주입.

## 배포 (Docker · Fly.io → 사내 VM)
- 웹 `frontend/Dockerfile`(Next.js standalone, 루트에서 빌드), 워커 `backend/Dockerfile`(Ubuntu 24.04 + Python 3.11, 한글 PDF 조판 포함).
- 1단계 Fly.io 도쿄(`deploy/fly/*.toml`), 2단계 사내 VM(`deploy/compose.yaml` + `deploy/hms.service`). 절차·점검 항목은 [docs/deploy.md](docs/deploy.md).

## 환경 변수
`.env.example`에 이름만 정리돼 있습니다. 값은 `.env`(커밋 금지) 또는 서버 측 시크릿 저장소에 둡니다.

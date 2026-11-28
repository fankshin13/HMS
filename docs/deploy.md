# 배포·운영 가이드

## 1. 결론 (제안)
- **1단계(지금~안정화): Fly.io 운영 대행** — 웹(Next.js)·워커(Python) 두 컨테이너를 도쿄(`nrt`) 지역에 올린다. Supabase(ap-northeast-1, 도쿄)와 같은 지역이라 DB·스토리지 왕복 지연이 작다.
- **2단계(기능 완료 후): 사내 클라우드 VM 이관** — 같은 Dockerfile 두 개를 Docker Compose + systemd 로 그대로 띄운다. 코드·이미지 변경 없이 환경 변수만 옮긴다.
- 데이터(DB·인증·파일)는 두 단계 모두 Supabase 에 남는다. 이관 대상은 **실행 서버(무상태)** 뿐이라 롤백이 쉽다.

| 구성 요소 | 1단계 (Fly.io) | 2단계 (사내 VM) |
|---|---|---|
| 웹 앱 | `hms-web` 앱, 1대 상시 + 자동 확장 | `web` 컨테이너, 사내 L7/Nginx 뒤 (TLS 종료) |
| 진단 워커 | `hms-worker` 앱, 1~3대 | `worker` 컨테이너, `--scale worker=N` |
| DB·인증·저장소 | Supabase (변경 없음) | Supabase (변경 없음) |
| 시크릿 | `fly secrets` | `deploy/.env` (권한 600, root 소유) |
| 배포 파일 | `deploy/fly/*.toml` | `deploy/compose.yaml`, `deploy/hms.service` |

> 비용은 머신 크기·대수·트래픽에 따라 달라지므로 Fly.io 공식 요금표로 확정한다. 기본안: 웹 shared-cpu-1x/512MB 1대, 워커 shared-cpu-2x/2GB 1대(대량 진단 시기만 3대).

## 2. 이미지
| 이미지 | Dockerfile | 기반 | 특징 |
|---|---|---|---|
| 웹 | `frontend/Dockerfile` (컨텍스트: 저장소 루트) | node:22-bookworm-slim | Next.js standalone, `node` 사용자, 약 420MB |
| 워커 | `backend/Dockerfile` (컨텍스트: `backend`) | ubuntu:24.04 + Python 3.11(uv) | WeasyPrint·Pango·HarfBuzz·Noto Sans CJK KR, UID 10001, 약 1.2GB |

- 두 컨테이너 모두 **읽기 전용 루트 파일시스템 + /tmp tmpfs + 권한(capability) 전부 제거** 상태에서 동작을 확인했다(웹 응답 200, 워커 한글 PDF 조판·글꼴 임베딩 확인).
- `NEXT_PUBLIC_*` 두 값은 브라우저 번들에 들어가는 **공개 값**이라 빌드 인자로 넣는다. `SUPABASE_SERVICE_ROLE_KEY`·`DATABASE_URL`·`INVITATION_TOKEN_SALT` 는 **실행 시 환경 변수로만** 주입하고 이미지·저장소·로그에 남기지 않는다.
- 보고서 글꼴을 Pretendard 로 바꾸려면 글꼴 파일을 볼륨으로 붙이고 `REPORT_FONT_DIR` 을 지정한다(없으면 Noto Sans CJK KR).

## 3. 1단계: Fly.io 배포
서비스 주소: https://hmva.fly.dev (웹 앱 `hmva`, 워커 앱 `hmva-worker`, 조직 `hms_dev`).

### 3-1. 권장: GitHub Actions 로 배포
1. Fly 조직 배포 토큰을 저장소 Settings → Secrets and variables → Actions 에 `FLY_API_TOKEN` 으로 등록(`production` 환경 사용 시 그 환경에 등록).
2. Fly 대시보드에서 워커 앱 시크릿(`DATABASE_URL`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`) 입력. `INVITATION_TOKEN_SALT` 는 두 앱에 같은 값으로 이미 대기(staged) 상태.
3. Actions → "Deploy to Fly.io" → Run workflow → 대상(web / worker / both) 선택.
- 웹 공개 값(`NEXT_PUBLIC_*`)은 `deploy/fly/web.toml` 의 `[build.args]` 에 있다.

### 3-2. 직접 배포 (flyctl 이 설치된 PC, 저장소 루트에서)
사전: `flyctl` 설치·로그인, 앱 이름 확정(`deploy/fly/*.toml` 의 `app`).

```bash
fly apps create hms-web
```
```bash
fly apps create hms-worker
```
```bash
fly secrets set -c deploy/fly/web.toml APP_URL=https://<도메인> INVITATION_TOKEN_SALT=<값>
```
```bash
fly secrets set -c deploy/fly/worker.toml DATABASE_URL=<값> SUPABASE_URL=https://<ref>.supabase.co SUPABASE_SERVICE_ROLE_KEY=<값>
```
```bash
fly deploy -c deploy/fly/web.toml --dockerfile frontend/Dockerfile --build-arg NEXT_PUBLIC_SUPABASE_URL=https://<ref>.supabase.co --build-arg NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=<공개 키> .
```
```bash
fly deploy -c deploy/fly/worker.toml --dockerfile backend/Dockerfile backend
```

- `DATABASE_URL` 은 Supabase 대시보드의 **Session pooler(세션 풀러, 접속 중계기)** 주소를 쓴다(워커는 장시간 연결 + `for update skip locked` 대기열).
- 배포 후 Supabase Auth 의 사이트 URL·리디렉션 URL(`<APP_URL>/auth/callback`)을 실제 도메인으로 등록한다.
- 대량 진단 시기: `fly scale count 3 -c deploy/fly/worker.toml` (끝나면 1로).

## 4. 2단계: 사내 클라우드 VM 이관
VM 권장 사양: 2 vCPU / 4GB 이상(워커 3대 병렬 시 4 vCPU / 8GB), Ubuntu 24.04 LTS, Docker Engine + Compose v2.
아웃바운드 허용: `<ref>.supabase.co`(HTTPS 443), Supabase 풀러(5432 또는 6543). 인바운드: 사내 L7 → VM 3000 만.

```bash
sudo git clone <저장소> /opt/hms
```
```bash
sudo install -m 600 -o root -g root deploy/env.example /opt/hms/deploy/.env
```
(`/opt/hms/deploy/.env` 에 값 입력)
```bash
cd /opt/hms && sudo docker compose -f deploy/compose.yaml --env-file deploy/.env up -d --build
```
```bash
sudo cp /opt/hms/deploy/hms.service /etc/systemd/system/ && sudo systemctl enable --now hms
```

전환 순서(무중단에 가깝게):
1. VM 에서 웹·워커 기동 → 사내 주소로 로그인·업로드·보고서 생성까지 확인.
2. Fly 워커를 0대로(`fly scale count 0 -c deploy/fly/worker.toml`) — 대기열은 DB 에 있으므로 VM 워커가 이어받는다.
3. DNS(또는 사내 L7)를 VM 으로 전환 → Supabase Auth 리디렉션 URL 갱신.
4. 1~2주 병행 관찰 후 Fly 앱 삭제, Fly 시크릿 폐기 후 **service role 키 재발급(rotate)**.

## 5. 운영 점검 (ISMS-P 관점)
- 접근통제: 운영 콘솔(Fly·Supabase) 계정 MFA, 최소 인원. VM 은 SSH 키 + 사내 점프 서버 경유.
- 시크릿: 시크릿 저장소 외 보관 금지, 담당자 변경·이관 시 재발급. 로그에 출력하지 않는다(코드는 오류 코드만 기록).
- 로그: `fly logs` / `docker compose logs` 를 사내 로그 수집기로 전송, 보존 기간은 사내 정책에 맞춘다.
- 백업: DB·저장소는 Supabase 백업 정책(요금제별)을 확인하고, 필요하면 정기 `pg_dump` 를 사내 백업 체계로.
- 원본 진단 로그: 제로 리텐션(보고서 다운로드 후 파기 / 기한 만료 시 워커가 자동 파기) 동작을 이관 후에도 확인.
- 패치: 기반 이미지 월 1회 재빌드(보안 업데이트 반영).

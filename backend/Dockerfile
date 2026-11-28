# 진단 워커 이미지 (파싱·판정 → 보고서 조판 → 보존 기한 관리)
# 빌드: docker build -t hms-worker backend
# 실행: docker run --env-file worker.env hms-worker
# 기반: Ubuntu 24.04 LTS(테스트·조판을 검증한 환경과 같은 배포판) + uv 로 설치한 Python 3.11
FROM ubuntu:24.04 AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Seoul \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_PYTHON_PREFERENCE=only-managed \
    DEBIAN_FRONTEND=noninteractive \
    MPLCONFIGDIR=/tmp/matplotlib

# WeasyPrint(PDF) 런타임: Pango·HarfBuzz, 한글 글꼴(Noto Sans CJK KR), 시간대
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 \
      fonts-noto-cjk tzdata ca-certificates python3-venv \
 && rm -rf /var/lib/apt/lists/*
# uv(PyPI) → Python 3.11 설치. 빌드 도구는 /opt/uv 에만 둔다.
RUN python3 -m venv /opt/uv \
 && /opt/uv/bin/pip install --no-cache-dir "uv==0.9.*" \
 && ln -s /opt/uv/bin/uv /usr/local/bin/uv \
 && uv python install 3.11

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY app ./app
COPY models ./models
COPY modules ./modules
COPY scripts ./scripts

# 비루트 실행. 쓰기는 /tmp 만 사용한다(원본 로그·보고서는 메모리→Supabase Storage).
RUN useradd --system --uid 10001 --no-create-home --home-dir /nonexistent worker
USER 10001
ENV PATH=/opt/venv/bin:$PATH

CMD ["python", "-m", "modules.worker"]

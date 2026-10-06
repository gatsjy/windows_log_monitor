# 빌드 컨텍스트는 저장소 루트 (docker-compose.yml 참고)

FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
# root 가 아닌 전용 계정으로 실행 (ISMS: 최소 권한)
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin wlm
COPY server/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
COPY server/app ./app
COPY server/migrations ./migrations
COPY web ./web
COPY config ./config
# 에이전트 스크립트 — 수집 PC 화면에서 설정이 채워진 설치 묶음(zip)으로 내려준다
COPY agent ./agent
RUN mkdir -p /app/archive && chown -R wlm:wlm /app/config /app/archive
# 8000 화면·API, 8001 에이전트 수집 전용 (app/serve.py)
EXPOSE 8000 8001
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"

# 개발용: 테스트 도구 + 코드 변경 시 자동 재시작
FROM base AS dev
COPY server/requirements-dev.txt ./requirements-dev.txt
RUN pip install -r requirements-dev.txt
COPY server/tests ./tests
COPY server/pyproject.toml ./pyproject.toml
USER wlm
CMD ["watchfiles", "--filter", "python", "python -m app.serve", "/app/app"]

# 운영용
FROM base AS runtime
USER wlm
CMD ["python", "-m", "app.serve"]

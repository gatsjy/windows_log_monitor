# syntax=docker/dockerfile:1
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
RUN mkdir -p /app/archive && chown -R wlm:wlm /app/config /app/archive
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"

# 개발용: 테스트 도구 + 코드 변경 시 자동 재시작
FROM base AS dev
COPY server/requirements-dev.txt ./requirements-dev.txt
RUN pip install -r requirements-dev.txt
COPY server/tests ./tests
COPY server/pyproject.toml ./pyproject.toml
USER wlm
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--reload", "--reload-dir", "/app/app", "--timeout-graceful-shutdown", "2"]

# 운영용
FROM base AS runtime
USER wlm
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--timeout-graceful-shutdown", "5"]

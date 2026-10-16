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
# 8000 화면·API(WLM_TLS=on 이면 HTTPS), 8001 평문 수집, 8002 TLS 수집 (app/serve.py). 8003 은 수집기 전용 내부(게시 안 함)
EXPOSE 8000 8001 8002
# TLS 를 켜면 화면 포트가 https 만 받으므로 설정을 읽는 모듈로 확인한다 (앱 전체는 불러오지 않음)
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "-m", "app.healthcheck"]

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

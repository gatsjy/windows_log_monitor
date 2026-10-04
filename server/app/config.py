"""환경변수 기반 설정.

모든 설정은 `WLM_` 접두사를 쓴다. 전체 목록과 설명은 `.env.example` 참고.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str) -> str:
    return os.environ.get(f"WLM_{name}", default)


def _int(name: str, default: int) -> int:
    return int(_env(name, str(default)))


def _list(name: str) -> tuple[str, ...]:
    return tuple(s.strip() for s in _env(name, "").split(",") if s.strip())


@dataclass(frozen=True)
class Settings:
    database_url: str = _env("DATABASE_URL", "postgresql://wlm:wlm@localhost:5432/wlm")
    # 에이전트(Fluent Bit)가 X-API-Key 헤더로 보내는 키. 콤마로 여러 개 (키 교체 기간용)
    ingest_api_keys: tuple[str, ...] = _list("INGEST_API_KEYS")
    # 에이전트 수집 전용 포트 (컨테이너 안). compose 가 호스트의 WLM_INGEST_PORT(기본 6976)를 여기로 연결한다.
    # 이 포트로는 /api/ingest 와 /healthz 만 열린다 → 화면(WLM_PORT)과 방화벽 정책을 나눌 수 있다
    ingest_listen_port: int = _int("INGEST_LISTEN_PORT", 8001)
    # 로그 로테이션 (월 단위 파티션이라 실제로는 최대 +1개월 더 남는다)
    #   DB 보관(db_retention_days): 화면에서 바로 검색되는 기간. 지나면 압축 파일로 보관(archive) 후 DB 에서 삭제
    #   전체 보관(retention_days): 보관 파일까지 포함한 기간. 지나면 보관 파일도 삭제 (ISMS 접속기록 1년 이상)
    #   db_retention_days >= retention_days 이면 파일 보관 없이 DB 에서 바로 삭제
    retention_days: int = _int("RETENTION_DAYS", 365)
    db_retention_days: int = _int("DB_RETENTION_DAYS", 90)
    archive_dir: str = _env("ARCHIVE_DIR", "/app/archive")
    # 마지막 수신 후 이 시간(초) 이내면 '온라인', stale 이내면 '지연', 그 이후는 '오프라인'
    heartbeat_online_sec: int = _int("HEARTBEAT_ONLINE_SEC", 90)
    heartbeat_stale_sec: int = _int("HEARTBEAT_STALE_SEC", 900)
    max_body_mb: int = _int("MAX_BODY_MB", 20)
    dashboard_dir: str = _env("DASHBOARD_DIR", "/app/config/dashboards")
    web_dir: str = _env("WEB_DIR", "/app/web")
    # 에이전트 설치 묶음(수집 PC 화면 > 내려받기): 에이전트 스크립트 위치, Fluent Bit 설치 파일 위치(반입 묶음의 agent-installers)
    agent_dir: str = _env("AGENT_DIR", "/app/agent")
    agent_installers_dir: str = _env("AGENT_INSTALLERS_DIR", "/app/agent-installers")
    # 에이전트가 접속할 호스트 쪽 수집 포트 (compose 의 WLM_INGEST_PORT). 설치 묶음의 settings.json 에 들어간다
    ingest_public_port: int = _int("INGEST_PORT", 6976)
    partition_months_ahead: int = _int("PARTITION_MONTHS_AHEAD", 2)
    log_level: str = _env("LOG_LEVEL", "INFO")

    # ---- 알림 (Phase 2) ----
    alerts_file: str = _env("ALERTS_FILE", "/app/config/alerts.yaml")
    # 알림 본문의 '검색 화면 열기' 링크에 쓰는 주소 (사용자가 브라우저로 접속하는 주소)
    public_url: str = _env("PUBLIC_URL", "http://localhost:8080").rstrip("/")
    # 알림 메시지에 시각을 표시할 시간대
    display_tz: str = _env("DISPLAY_TZ", "Asia/Seoul")
    # 메일 발송 서버. 비밀번호 같은 비밀값은 config/alerts.yaml 이 아니라 환경변수(.env)에만 둔다
    smtp_host: str = _env("SMTP_HOST", "")
    smtp_port: int = _int("SMTP_PORT", 587)
    smtp_security: str = _env("SMTP_SECURITY", "starttls")  # none | starttls | ssl
    smtp_user: str = _env("SMTP_USER", "")
    smtp_password: str = _env("SMTP_PASSWORD", "")
    smtp_from: str = _env("SMTP_FROM", "log-monitor@localhost")

    # ---- 인증 (Phase 2) — 기본값은 ISMS 심사에서 흔히 요구하는 수준 ----
    session_idle_min: int = _int("SESSION_IDLE_MIN", 30)          # 이 시간 동안 조작이 없으면 로그아웃
    session_max_hours: int = _int("SESSION_MAX_HOURS", 12)        # 로그인 후 최대 유지 시간
    login_max_failures: int = _int("LOGIN_MAX_FAILURES", 5)       # 연속 실패 시 계정 잠금
    login_lockout_min: int = _int("LOGIN_LOCKOUT_MIN", 10)        # 잠금 시간
    password_max_age_days: int = _int("PASSWORD_MAX_AGE_DAYS", 90)  # 비밀번호 변경 주기 (0 = 사용 안 함)
    # HTTPS(리버스 프록시) 뒤에서 운영하면 true → 쿠키가 HTTPS 에서만 전송된다
    cookie_secure: bool = _env("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")
    # 사용자가 하나도 없을 때 만드는 admin 계정의 초기 비밀번호 (비우면 무작위 생성 후 서버 로그에 1회 출력)
    admin_initial_password: str = _env("ADMIN_INITIAL_PASSWORD", "")
    login_notice: str = _env(
        "LOGIN_NOTICE", "이 시스템은 인가된 사용자만 사용할 수 있습니다. 모든 접속과 작업 내역은 기록됩니다."
    )
    api_docs: bool = _env("API_DOCS", "true").lower() in ("1", "true", "yes")  # /docs (OpenAPI) 노출 여부
    password_hash_n: int = _int("PASSWORD_HASH_N", 2**17)          # scrypt 비용 (테스트에서만 낮춘다)

    # ---- 환경설정 비밀값 암호화 키 (DB 에 저장하는 SMTP·Oracle 비밀번호 등) ----
    secret_key: str = _env("SECRET_KEY", "")


settings = Settings()

"""환경변수 기반 설정.

모든 설정은 `WLM_` 접두사를 쓴다. 전체 목록과 설명은 `.env.example` 참고.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from zoneinfo import ZoneInfo


def _env(name: str, default: str) -> str:
    return os.environ.get(f"WLM_{name}", default)


def _int(name: str, default: int) -> int:
    return int(_env(name, str(default)))


def _int_opt(name: str) -> int | None:
    """값이 없거나 빈 값이면 None — compose 가 설정하지 않은 변수를 빈 값으로 넘길 때 다른 설정을 따르게"""
    value = _env(name, "").strip()
    return int(value) if value else None


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
    # 컨테이너 안 화면·API 포트 (compose 가 WLM_PORT 를 여기로). 헬스체크(app.healthcheck)도 읽는다
    web_listen_port: int = _int("LISTEN_PORT", 8000)
    # TLS 수집(WLM_TLS=on 일 때, 호스트 WLM_INGEST_TLS_PORT 6977)과 수집기(collector) 전용 내부 수집(게시 안 함) — ADR-036
    ingest_tls_listen_port: int = _int("INGEST_TLS_LISTEN_PORT", 8002)
    internal_ingest_listen_port: int = _int("INTERNAL_INGEST_LISTEN_PORT", 8003)
    # 로그 로테이션 (월 단위 파티션이라 실제로는 최대 +1개월 더 남는다)
    #   DB 보관(db_retention_days): 화면에서 바로 검색되는 기간. 지나면 압축 파일로 보관(archive) 후 DB 에서 삭제
    #   전체 보관(retention_days): 보관 파일까지 포함한 기간. 지나면 보관 파일도 삭제 (ISMS 접속기록 1년 이상)
    #   db_retention_days >= retention_days 이면 파일 보관 없이 DB 에서 바로 삭제
    retention_days: int = _int("RETENTION_DAYS", 365)
    db_retention_days: int = _int("DB_RETENTION_DAYS", 90)
    # 기록 종류별 보관기간 (ADR-040, 개인정보의 안전성 확보조치 기준 제5조·제8조)
    #   알림 이력(처리 기록·무음 포함): 기본은 로그와 같다 — 사고 대응 증적
    #   감사로그(이 시스템의 접속·권한 부여·변경·말소 기록): 최소 3년 — 로그와 같은 날 지우면 권한 변경 기록이 1년 만에 사라졌다
    #   점검 보고서(점검 증적): 기본 3년
    alert_retention_days: int = _int_opt("ALERT_RETENTION_DAYS") or retention_days
    audit_retention_days: int = _int("AUDIT_RETENTION_DAYS", 1095)
    # 진료정보 등 민감정보를 처리하는 시스템의 접속기록을 모으는 사이트(병원) — 로그 보관 법정 최소를 2년으로 보고 경고한다 (제8조)
    sensitive_access_log: bool = _env("SENSITIVE_ACCESS_LOG", "off").lower() in ("1", "on", "true", "yes")
    report_retention_days: int = _int("REPORT_RETENTION_DAYS", 1095)
    archive_dir: str = _env("ARCHIVE_DIR", "/app/archive")
    # DB 백업 일정 (backup 서비스가 실제로 돌린다, deploy/backup/backup.sh). 여기서는 화면 표시와 '오래됨' 판단에만 쓴다
    backup_time: str = _env("BACKUP_TIME", "02:30")
    backup_keep: int = _int("BACKUP_KEEP", 14)
    backup_verify_weekday: int = _int("BACKUP_VERIFY_WEEKDAY", 7)  # 1=월 … 7=일, 0=자동 복구 시험 안 함
    # 점검 보고서 정기 실행 (일정·받는 곳은 환경설정 화면). 끄면 '지금 만들기'만 된다 — 테스트, 또는 여러 대 중 한 대만 돌릴 때
    report_scheduler: bool = _env("REPORT_SCHEDULER", "on").lower() in ("1", "on", "true", "yes")
    # 마지막 수신 후 이 시간(초) 이내면 '온라인', stale 이내면 '지연', 그 이후는 '오프라인'
    heartbeat_online_sec: int = _int("HEARTBEAT_ONLINE_SEC", 90)
    heartbeat_stale_sec: int = _int("HEARTBEAT_STALE_SEC", 900)
    max_body_mb: int = _int("MAX_BODY_MB", 20)
    # 화면 검색·통계 쿼리 하나의 최대 시간(초, 0 = 없음). 연결 풀(10개)을 수집과 나눠 쓰므로 느린 검색이 쌓여
    # 수집까지 막히지 않게 한다. 알림 엔진·점검 보고서는 놓치면 안 되는 작업이라 걸지 않는다 (ADR-035)
    search_timeout_sec: int = _int("SEARCH_TIMEOUT_SEC", 30)
    # 알림 규칙 쿼리 하나의 최대 시간(초, 0 = 없음, ADR-045). 넘기면 그 규칙만 '시간 초과'로 표시하고 다음 규칙을 평가한다 —
    # 무거운 규칙 하나가 평가 전체를 멈추지 않게. 화면 조회 자리(SEARCH_SLOTS)는 쓰지 않는다
    alert_rule_timeout_sec: int = _int("ALERT_RULE_TIMEOUT_SEC", 20)
    # 알림 전송기(ADR-045). 시험에서만 끈다(conftest) — 시험은 dispatcher.drain() 을 직접 부른다
    alert_dispatcher: bool = _env("ALERT_DISPATCHER", "on").lower() in ("1", "on", "true", "yes")
    # 알림 대상 정기 시험 전송 (B-34): 이 요일·시각(표시 시간대) 뒤 첫 감시 때, 규칙·대체 경로가 쓰는 받는 곳마다 시험 알림 한 건.
    # 알림 경로(메일 비밀번호 만료·웹훅 토큰 폐기)가 깨진 것을 실제 알림이 나기 전에 안다. 1=월 … 7=일, 0=안 함
    alert_test_weekday: int = _int("ALERT_TEST_WEEKDAY", 1)
    alert_test_time: str = _env("ALERT_TEST_TIME", "09:00")
    # 백업·보관 파일 외부 저장소 복제 (B-17, backup 서비스가 한다). 켜져 있으면 화면·보고서가 복제가 밀리거나 실패한 것을 알린다
    replica: bool = _env("REPLICA", "off").lower() in ("1", "on", "true", "yes")
    dashboard_dir: str = _env("DASHBOARD_DIR", "/app/config/dashboards")
    web_dir: str = _env("WEB_DIR", "/app/web")
    # 에이전트 설치 묶음(수집 PC 화면 > 내려받기): 에이전트 스크립트 위치, Fluent Bit 설치 파일 위치(반입 묶음의 agent-installers)
    agent_dir: str = _env("AGENT_DIR", "/app/agent")
    agent_installers_dir: str = _env("AGENT_INSTALLERS_DIR", "/app/agent-installers")
    # 에이전트가 접속할 호스트 쪽 수집 포트 (compose 의 WLM_INGEST_PORT). 설치 묶음의 settings.json 에 들어간다
    ingest_public_port: int = _int("INGEST_PORT", 6976)
    ingest_tls_public_port: int = _int("INGEST_TLS_PORT", 6977)
    # 평문 수집 리스너(6976). 모든 에이전트를 TLS 로 옮긴 뒤 off — 리스너를 띄우지 않아 연결 자체가 거부된다
    ingest_plain: bool = _env("INGEST_PLAIN", "on").lower() in ("1", "on", "true", "yes")
    # 수집 리스너 keep-alive(초). Fluent Bit 의 유휴 연결(30초)보다 길어야 재사용 순간에 끊기는 경합이 없다
    ingest_keepalive_sec: int = _int("INGEST_KEEPALIVE_SEC", 75)
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
    # https 요청의 세션 쿠키는 자동으로 Secure. true 면 http 에서도 Secure 를 강제하고 http 로그인은 거부(조용히 안 되는 대신 안내)
    cookie_secure: bool = _env("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")

    # ---- HTTPS·에이전트 TLS (ADR-036, docs/AIRGAP.md §7.5) ----
    # on: 화면(8000)과 TLS 수집(8002)을 api 가 직접 TLS 로. 그 밖의 값이면 기동 거부(app.tlsutil.preflight)
    tls_mode: str = _env("TLS", "off").strip().lower()
    tls_cert_file: str = _env("TLS_CERT_FILE", "/app/tls/server.crt")   # 리프 먼저, 중간 CA 포함
    tls_key_file: str = _env("TLS_KEY_FILE", "/app/tls/server.key")     # 암호 없는 PEM, 0600 소유자 10001(api)
    tls_ca_file: str = _env("TLS_CA_FILE", "/app/tls/ca.crt")           # 에이전트 설치 묶음에 넣는 루트 CA(공개값)
    # X-Forwarded-For/Proto 를 믿을 리버스 프록시 IP·CIDR. 비우면 프록시 헤더를 보지 않는다('*'·/0 은 기동 거부)
    trusted_proxies: tuple[str, ...] = _list("TRUSTED_PROXIES")
    # https 응답의 HSTS 초. 비우면 보내지 않음, 0 이면 'max-age=0' 을 보내 브라우저에 남은 HSTS 를 지운다(되돌릴 때)
    hsts_max_age: int | None = int(_env("HSTS_MAX_AGE", "").strip()) if _env("HSTS_MAX_AGE", "").strip() else None

    @property
    def tls(self) -> bool:
        return self.tls_mode == "on"
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


def display_zone() -> ZoneInfo:
    """표시 시간대(WLM_DISPLAY_TZ). 이름이 틀리면(.env 오타) 멈추지 않고 UTC 로 — 알림·수집·보고서가 같은 규칙을 쓴다.
    잘못된 이름은 기동 때 경고한다(main.lifespan)."""
    try:
        return ZoneInfo(settings.display_tz)
    except Exception:  # noqa: BLE001 - ZoneInfoNotFoundError·ValueError(경로 문자 등) 모두 UTC 로
        return ZoneInfo("UTC")

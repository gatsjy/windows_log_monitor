"""테스트 공통 설정.

app 모듈이 import 되기 전에 환경변수를 바꿔야 한다 (settings 는 import 시점에 정해짐).
- DB: 개발 DB 대신 같은 서버의 별도 DB(<이름>_test)를 쓴다. 통합 테스트(test_api_*.py)만 실제로 접속한다.
- 비밀번호 해시 비용을 낮춰 테스트를 빠르게 한다.
- 알림 엔진이 실제 메일을 보내지 않도록 존재하지 않는 규칙 파일을 가리킨다.
"""

from __future__ import annotations

import os
import tempfile

import pytest

_dev_url = os.environ.get("WLM_DATABASE_URL", "postgresql://wlm:wlm@localhost:5432/wlm")
_base, _, _dbname = _dev_url.rpartition("/")
TEST_DB_NAME = f"{_dbname}_test"
os.environ["WLM_DATABASE_URL"] = f"{_base}/{TEST_DB_NAME}"
os.environ["WLM_ADMIN_DATABASE_URL"] = _dev_url  # 테스트 DB 를 만들고 지울 때 접속할 곳
os.environ["WLM_PASSWORD_HASH_N"] = str(2**12)
os.environ["WLM_ADMIN_INITIAL_PASSWORD"] = "Init#Pass2026"
os.environ["WLM_INGEST_API_KEYS"] = "test-key"
_tmp = tempfile.mkdtemp(prefix="wlm-test-")
os.environ["WLM_ALERTS_FILE"] = os.path.join(_tmp, "alerts.yaml")
os.environ["WLM_DASHBOARD_DIR"] = os.path.join(_tmp, "dashboards")
os.environ["WLM_ARCHIVE_DIR"] = os.path.join(_tmp, "archive")
os.environ["WLM_AGENT_INSTALLERS_DIR"] = os.path.join(_tmp, "agent-installers")
os.environ["WLM_INGEST_PORT"] = "6976"
os.environ["WLM_DB_RETENTION_DAYS"] = "90"
os.environ["WLM_RETENTION_DAYS"] = "365"
# compose 가 .env 의 값을 api 컨테이너에 넘기므로, 운영자가 바꿔 둔 값에 테스트 결과가 흔들리지 않게 고정한다
os.environ["WLM_DISPLAY_TZ"] = "Asia/Seoul"
os.environ["WLM_BACKUP_TIME"] = "02:30"
os.environ["WLM_BACKUP_KEEP"] = "14"
os.environ["WLM_BACKUP_VERIFY_WEEKDAY"] = "7"
os.environ["WLM_SECRET_KEY"] = "test-secret-key-0123456789abcdef"
# 점검 보고서 정기 실행은 실제 시각으로 돌아 테스트 DB 에 보고서를 만들어 버린다 → 끄고, 테스트가 tick(now) 을 직접 부른다
os.environ["WLM_REPORT_SCHEDULER"] = "off"
# 개발 서버를 TLS 로 띄워 둔 채(WLM_TLS=on, AIRGAP.md §13) 시험을 돌려도 평문 전제의 시험이 흔들리지 않게 고정한다
os.environ["WLM_TLS"] = "off"
os.environ["WLM_INGEST_PLAIN"] = "on"
os.environ["WLM_TRUSTED_PROXIES"] = ""
os.environ["WLM_HSTS_MAX_AGE"] = ""
os.environ["WLM_COOKIE_SECURE"] = "false"
os.environ["WLM_SEARCH_TIMEOUT_SEC"] = "30"
os.environ["WLM_SENSITIVE_ACCESS_LOG"] = "off"
# 알림 전송기는 시험에서 돌지 않는다 — 시험이 dispatcher.drain() 으로 보낸다 (ADR-045, 백그라운드와 겨루지 않게)
os.environ["WLM_ALERT_DISPATCHER"] = "off"
os.environ["WLM_ALERT_RULE_TIMEOUT_SEC"] = "20"
# 정기 시험 전송은 감시가 실제 시각으로 보낸다 — 시험에서는 끄고 watchdog.scheduled_tests(now) 를 직접 부른다 (B-34)
os.environ["WLM_ALERT_TEST_WEEKDAY"] = "0"


@pytest.fixture(scope="module", autouse=True)
def _fresh_alert_engine():
    """통합 시험 모듈마다 시험 DB 를 새로 만든다 → 알림 엔진도 처음 설치한 서버처럼 시작한다.
    엔진은 프로세스에 하나라, 앞 모듈이 적용한 설정이 다음 모듈의 새 DB 에 '설정 변경'으로 기록·알림되지 않게 (ADR-043)."""
    from app.alerts.engine import engine

    engine.forget()
    yield

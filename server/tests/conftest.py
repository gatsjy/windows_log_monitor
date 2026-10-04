"""테스트 공통 설정.

app 모듈이 import 되기 전에 환경변수를 바꿔야 한다 (settings 는 import 시점에 정해짐).
- DB: 개발 DB 대신 같은 서버의 별도 DB(<이름>_test)를 쓴다. 통합 테스트(test_api_*.py)만 실제로 접속한다.
- 비밀번호 해시 비용을 낮춰 테스트를 빠르게 한다.
- 알림 엔진이 실제 메일을 보내지 않도록 존재하지 않는 규칙 파일을 가리킨다.
"""

from __future__ import annotations

import os
import tempfile

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
os.environ["WLM_SECRET_KEY"] = "test-secret-key-0123456789abcdef"

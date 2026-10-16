"""컨테이너 상태 확인 (Dockerfile HEALTHCHECK, 폐쇄망 install.sh): python -m app.healthcheck → 0 정상, 1 실패.

app.config 만 불러온다 — 30초마다 도는 확인이 FastAPI 앱 전체를 불러오지 않게.
WLM_TLS=on 이면 화면 포트가 HTTPS 만 받으므로 https 로 부른다(ADR-036).
"""

from __future__ import annotations

import ssl
import sys
import urllib.request

from .config import settings


def url() -> str:
    return f"{'https' if settings.tls else 'http'}://127.0.0.1:{settings.web_listen_port}/healthz"


def main() -> int:
    # 같은 컨테이너 안의 자기 자신(루프백)을 부르므로 인증서 이름 확인이 불가능하고 의미도 없다 — 확인하지 않는다.
    # 인증서 자체의 문제(만료·이름)는 기동 로그와 매일 점검(main._maintenance_loop)이 알린다
    context = ssl._create_unverified_context() if settings.tls else None
    try:
        with urllib.request.urlopen(url(), timeout=4, context=context) as resp:
            return 0 if resp.status == 200 else 1
    except OSError as exc:
        print(f"상태 확인 실패: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

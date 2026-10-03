"""Oracle 연결과 쿼리 실행 (python-oracledb thin 모드 — Oracle Client 설치 불필요, Apache-2.0/UPL).

접속 방식 (환경설정 > 외부 연동 > Oracle):
  tns      TNS 이름: config/oracle/tnsnames.ora 의 별칭 (화면에서 파일 내용도 편집 가능)
  sid      호스트 + 포트 + SID
  service  호스트 + 포트 + 서비스 이름
  dsn      접속 문자열 직접 입력 (Easy Connect "host:port/service" 또는 (DESCRIPTION=...))

모든 함수는 동기(블로킹) — 호출하는 쪽에서 asyncio.to_thread 로 실행한다.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from .config import settings

MODES = {"tns": "TNS 이름", "sid": "호스트 + SID", "service": "호스트 + 서비스 이름", "dsn": "접속 문자열"}
CALL_TIMEOUT_MS = 15_000
MAX_QUERY_ROWS = 500


class OracleError(Exception):
    """사용자에게 보여줄 Oracle 관련 오류."""


def tns_dir() -> Path:
    return Path(settings.alerts_file).parent / "oracle"


def tns_file() -> Path:
    return tns_dir() / "tnsnames.ora"


def tns_aliases(text: str | None = None) -> list[str]:
    """tnsnames.ora 의 최상위 별칭 목록 (괄호 깊이 0 에서 '이름 =' 형태)."""
    if text is None:
        path = tns_file()
        text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    aliases, depth = [], 0
    for line in text.splitlines():
        stripped = line.split("#", 1)[0]
        if depth == 0:
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+(?:\s*,\s*[A-Za-z0-9_.\-]+)*)\s*=", stripped)
            if m:
                aliases += [a.strip() for a in m.group(1).split(",") if a.strip()]
        depth += stripped.count("(") - stripped.count(")")
        depth = max(depth, 0)
    return aliases


@dataclass
class OracleConn:
    """접속 정보. password 는 복호화된 값 (로그·화면에 내보내지 않는다)."""

    mode: str
    user: str
    password: str
    tns_alias: str = ""
    host: str = ""
    port: int = 1521
    sid: str = ""
    service_name: str = ""
    dsn: str = ""

    @classmethod
    def from_config(cls, config: dict[str, Any], password: str) -> OracleConn:
        mode = config.get("mode", "service")
        if mode not in MODES:
            raise OracleError(f"알 수 없는 접속 방식: {mode}")
        conn = cls(mode=mode, user=str(config.get("user", "")).strip(), password=password,
                   tns_alias=str(config.get("tns_alias", "")).strip(), host=str(config.get("host", "")).strip(),
                   port=int(config.get("port") or 1521), sid=str(config.get("sid", "")).strip(),
                   service_name=str(config.get("service_name", "")).strip(), dsn=str(config.get("dsn", "")).strip())
        conn.validate()
        return conn

    def validate(self) -> None:
        if not self.user:
            raise OracleError("사용자(계정)를 입력하세요")
        required = {"tns": ["tns_alias"], "sid": ["host", "sid"], "service": ["host", "service_name"], "dsn": ["dsn"]}
        labels = {"tns_alias": "TNS 이름", "host": "호스트", "sid": "SID", "service_name": "서비스 이름", "dsn": "접속 문자열"}
        missing = [labels[f] for f in required[self.mode] if not getattr(self, f)]
        if missing:
            raise OracleError(f"{', '.join(missing)} 을(를) 입력하세요")
        if not 1 <= self.port <= 65535:
            raise OracleError("포트 번호가 올바르지 않습니다")

    def describe(self) -> str:
        """화면 표시용 (비밀번호 제외)."""
        target = {
            "tns": f"TNS {self.tns_alias}",
            "sid": f"{self.host}:{self.port} SID={self.sid}",
            "service": f"{self.host}:{self.port}/{self.service_name}",
            "dsn": self.dsn if len(self.dsn) < 80 else self.dsn[:77] + "...",
        }[self.mode]
        return f"{self.user}@{target}"

    def connect(self):
        import oracledb  # 지연 import

        if not self.password:
            raise OracleError("비밀번호가 저장되어 있지 않습니다")
        kwargs: dict[str, Any] = {"user": self.user, "password": self.password, "tcp_connect_timeout": 10}
        if self.mode == "tns":
            if self.tns_alias.upper() not in {a.upper() for a in tns_aliases()}:
                raise OracleError(f"tnsnames.ora 에 '{self.tns_alias}' 별칭이 없습니다 (환경설정 > Oracle > tnsnames.ora)")
            kwargs.update(dsn=self.tns_alias, config_dir=str(tns_dir()))
        elif self.mode == "sid":
            kwargs.update(host=self.host, port=self.port, sid=self.sid)
        elif self.mode == "service":
            kwargs.update(host=self.host, port=self.port, service_name=self.service_name)
        else:
            kwargs.update(dsn=self.dsn)
        try:
            conn = oracledb.connect(**kwargs)
        except oracledb.Error as exc:
            raise OracleError(f"접속 실패: {exc}") from exc
        conn.call_timeout = CALL_TIMEOUT_MS
        return conn


# ------------------------------------------------------------------ 작업

def test_connection(conn_info: OracleConn) -> dict[str, Any]:
    import oracledb

    try:
        with conn_info.connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT SYS_CONTEXT('USERENV','DB_NAME'), SYS_CONTEXT('USERENV','SERVICE_NAME'),"
                        " SYS_CONTEXT('USERENV','CURRENT_SCHEMA'), SYSTIMESTAMP FROM DUAL")
            db_name, service, schema, now = cur.fetchone()
            return {"version": conn.version, "db_name": db_name, "service_name": service, "schema": schema,
                    "server_time": str(now)}
    except oracledb.Error as exc:
        raise OracleError(f"Oracle 오류: {exc}") from exc


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if hasattr(value, "read"):  # LOB
        data = value.read()
        return data[:4000] if isinstance(data, str) else f"<{len(data)} bytes>"
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    return str(value)


_READ_ONLY_START = re.compile(r"^\s*(SELECT|WITH)\b", re.IGNORECASE)


def _strip_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    return "\n".join(line.split("--", 1)[0] for line in sql.splitlines()).strip()


def run_query(conn_info: OracleConn, sql: str, max_rows: int = 100) -> dict[str, Any]:
    """조회 전용 쿼리 실행 (SELECT / WITH 만). 읽기 전용 트랜잭션 + 행 수 제한."""
    import oracledb

    body = _strip_comments(sql).rstrip(";").strip()
    if not _READ_ONLY_START.match(body):
        raise OracleError("조회(SELECT / WITH) 쿼리만 실행할 수 있습니다")
    if ";" in body:
        raise OracleError("한 번에 한 문장만 실행할 수 있습니다")
    max_rows = max(1, min(max_rows, MAX_QUERY_ROWS))
    try:
        with conn_info.connect() as conn, conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute(body)
            columns = [d[0] for d in cur.description or []]
            fetched = cur.fetchmany(max_rows + 1)
            # LOB 은 연결이 열려 있을 때 읽어야 한다
            rows = [[_plain(v) for v in row] for row in fetched[:max_rows]]
            conn.rollback()
    except oracledb.Error as exc:
        raise OracleError(f"Oracle 오류: {exc}") from exc
    return {"columns": columns, "rows": rows, "truncated": len(fetched) > max_rows}


def execute(conn_info: OracleConn, sql: str, binds: dict[str, Any], commit: bool = True,
            clob_binds: tuple[str, ...] = ()) -> int:
    """알림 INSERT/프로시저 호출 등 한 문장 실행. commit=False 면 실행 후 되돌린다 (시험용)."""
    import oracledb

    try:
        with conn_info.connect() as conn, conn.cursor() as cur:
            sizes = {k: oracledb.DB_TYPE_CLOB for k in clob_binds if k in binds}
            if sizes:
                cur.setinputsizes(**sizes)
            cur.execute(sql, binds)
            count = cur.rowcount
            if commit:
                conn.commit()
            else:
                conn.rollback()
            return count
    except oracledb.IntegrityError as exc:
        if "ORA-00001" in str(exc) and commit:
            return 0  # 같은 키가 이미 있음 = 이전 시도에서 이미 들어감 (재시도 중복 방지)
        raise OracleError(f"Oracle 오류: {exc}") from exc
    except oracledb.Error as exc:
        raise OracleError(f"Oracle 오류: {exc}") from exc

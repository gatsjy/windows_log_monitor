"""알림 기능의 상태 판단 (ADR-045, BACKLOG B-34) — 순수 함수. 화면 상태 띠·/healthz/alerts·점검 보고서가 같이 쓴다.

예전 화면은 설정 오류와 마지막 오류가 비어 있으면 늘 초록이었다 — 평가가 몇 시간째 멈춰도, 메일 서버가 하루 종일 실패해도.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

BACKLOG_WARN = timedelta(minutes=5)       # 보낼 차례가 된 지 이만큼 지난 알림이 있으면 '밀림'
TARGET_DOWN = timedelta(minutes=15)       # 받는 곳이 이만큼 계속 실패하면 '모두 안 됨' 판단에 넣는다
DISPATCH_STALL = timedelta(seconds=120)

RULE_LABELS = {"off": "꺼짐", "never": "평가 전", "error": "오류", "timeout": "시간 초과", "truncated": "일부만",
               "slow": "느림", "stale": "멈춤", "ok": "정상"}


def engine_stall(interval_sec: int, rule_timeout_sec: int) -> timedelta:
    """평가가 이만큼 나아가지 않으면 멈춘 것. 규칙 하나가 시간 상한까지 걸릴 수 있으니 그 두 배에 여유를 더한다."""
    return timedelta(seconds=max(3 * interval_sec, 2 * rule_timeout_sec + 30, 120))


def rule_state(enabled: bool, run: dict[str, Any] | None, rule_timeout_sec: int, interval_sec: int, now: datetime) -> str:
    if not enabled:
        return "off"
    if not run or not run.get("last_run_at"):
        return "never"
    if run.get("error_kind") == "timeout":
        return "timeout"
    if run.get("error"):
        return "error"
    if run.get("truncated"):
        return "truncated"
    if (run.get("duration_ms") or 0) >= max(5000, rule_timeout_sec * 500):
        return "slow"
    if now - run["last_run_at"] > timedelta(seconds=3 * interval_sec):
        return "stale"
    return "ok"


def _ago(now: datetime, at: datetime | None) -> str:
    if at is None:
        return "기록 없음"
    sec = max(0, int((now - at).total_seconds()))
    return f"{sec // 3600}시간 {sec % 3600 // 60}분" if sec >= 3600 else f"{sec // 60}분" if sec >= 60 else f"{sec}초"


def _names(names: list[str], limit: int = 5) -> str:
    shown = ", ".join(f"'{n}'" for n in names[:limit])
    return shown + (f" 외 {len(names) - limit}개" if len(names) > limit else "")


def assess(engine: dict[str, Any], dispatcher: dict[str, Any], queue: list[dict[str, Any]], gave_up_24h: int,
           rules: list[dict[str, Any]], used_targets: set[str], now: datetime) -> dict[str, Any]:
    """engine = AlertEngine.health_snapshot(), dispatcher = Dispatcher.status() + enabled,
    rules = [{name, enabled, run}], used_targets = 켜진 규칙의 받는 곳. 돌려주는 값 = {status, problems, rules}."""
    problems: list[dict[str, Any]] = []

    def add(level: str, code: str, text: str, n: int = 1) -> None:
        problems.append({"level": level, "code": code, "text": text, "n": n})

    interval, timeout = engine["interval_sec"], engine["rule_timeout_sec"]
    if not engine.get("standby"):
        progress = engine.get("progress_at")
        if not engine.get("running") or progress is None or now - progress > engine_stall(interval, timeout):
            current = engine.get("current_rule")
            add("bad", "evaluator_down",
                f"알림 규칙 평가가 {_ago(now, progress)}째 멈춰 있습니다"
                + (f" (규칙 '{current}' 평가 중)" if current else "") + " — 계속되면 서버 로그를 확인하세요")
        elif (engine.get("cycle_sec") or 0) > interval:
            add("warn", "evaluator_slow", f"규칙을 한 바퀴 평가하는 데 {engine['cycle_sec']:.0f}초 — 평가 주기({interval}초)보다 깁니다")

    if not dispatcher.get("enabled", True):
        add("bad", "dispatcher_off", "알림 전송이 꺼져 있습니다 (WLM_ALERT_DISPATCHER) — 알림이 기록만 되고 나가지 않습니다")
    elif not dispatcher.get("standby"):
        progress = dispatcher.get("progress_at")
        if not dispatcher.get("running") or progress is None or now - progress > DISPATCH_STALL:
            due = sum(q["due"] for q in queue)
            add("bad", "dispatcher_down", f"알림 전송이 멈춰 있습니다 — 보낼 알림 {due:,}건이 쌓여 있습니다", due)

    oldest = min((q["oldest_due_at"] for q in queue if q.get("oldest_due_at")), default=None)
    if oldest is not None and now - oldest > BACKLOG_WARN:
        due = sum(q["due"] for q in queue)
        add("warn", "backlog", f"보낼 알림 {due:,}건이 밀려 있습니다 (가장 오래 기다린 알림 {_ago(now, oldest)})", due)

    failing = {name: t for name, t in (dispatcher.get("targets") or {}).items() if t.get("failing_since")}
    waiting = {q["notifier"]: q["queued"] for q in queue}
    for name, t in sorted(failing.items()):
        add("warn", "target_failing",
            f"'{name}'(으)로 {_ago(now, t['failing_since'])}째 보내지 못하고 있습니다: {(t.get('last_error') or '')[:120]}"
            f" — 대기 {waiting.get(name, 0):,}건. 고친 뒤 '테스트 발송'을 누르면 바로 다시 보냅니다")
    used_down = [n for n in used_targets if n in failing and now - failing[n]["failing_since"] >= TARGET_DOWN]
    if used_targets and len(used_down) == len(used_targets):
        add("bad", "targets_all_down", "규칙이 쓰는 모든 알림 대상으로 15분 넘게 보내지 못하고 있습니다 — 알림이 아무에게도 가지 않습니다")
    if gave_up_24h:
        add("warn", "gave_up", f"최근 24시간 동안 보내지 못하고 재시도를 멈춘 알림 {gave_up_24h:,}건", gave_up_24h)

    states: dict[str, list[str]] = {}
    for r in rules:
        r["state"] = rule_state(r["enabled"], r.get("run"), timeout, interval, now)
        states.setdefault(r["state"], []).append(r["name"])
    if broken := states.get("error", []) + states.get("timeout", []):
        add("warn", "rule_error", f"동작하지 않는 규칙 {len(broken)}개: {_names(broken)} — 조건을 좁히고 미리보기로 확인하세요", len(broken))
    if cut := states.get("truncated"):
        add("warn", "rule_truncated", f"기준을 넘은 묶음이 너무 많아 일부만 알린 규칙 {len(cut)}개: {_names(cut)}"
                                      " (나머지는 다음 평가에서 알립니다)", len(cut))
    if slow := states.get("slow"):
        add("warn", "rule_slow", f"평가가 느린 규칙 {len(slow)}개: {_names(slow)}", len(slow))
    gaps = [r["name"] for r in rules if r["enabled"] and (r.get("run") or {}).get("last_gap")
            and now - r["run"]["last_gap"]["at"] < timedelta(hours=24)]
    if gaps:
        add("warn", "rule_gap", f"평가가 늦어 로그 일부를 확인하지 못한 규칙 {len(gaps)}개: {_names(gaps)}", len(gaps))

    levels = {p["level"] for p in problems}
    status = "down" if "bad" in levels else "warn" if levels else "ok"
    return {"status": status, "problems": sorted(problems, key=lambda p: p["level"] != "bad"), "checked_at": now}


def public_view(health: dict[str, Any], version: str) -> dict[str, Any]:
    """로그인 없는 /healthz/alerts 용 — 수와 코드만 (규칙·받는 곳·PC 이름, 오류 문구 없음)."""
    return {"status": health["status"], "checked_at": health["checked_at"], "version": version,
            "problems": sorted({p["code"] for p in health["problems"]}),
            "counts": {p["code"]: p["n"] for p in health["problems"]}}


# ---------------------------------------------------------------- 지금 상태 (화면·/healthz/alerts·점검 보고서 공용)
CACHE_SEC = 10   # 로그인 없이 부를 수 있는 /healthz/alerts 가 DB 를 두드리지 않게
_cache: tuple[datetime, dict[str, Any]] | None = None
_lock: tuple[Any, Any] | None = None


async def current(now: datetime | None = None, *, fresh: bool = False) -> dict[str, Any]:
    """엔진·전송기 메모리 + 전송 대기열을 모아 assess. 한 번에 하나만 계산하고(연결 1개) 10초 동안 재사용한다."""
    import asyncio

    from .. import repository
    from .dispatcher import dispatcher
    from .engine import engine

    global _cache, _lock
    now = now or datetime.now(UTC)
    if not fresh and _cache and now - _cache[0] < timedelta(seconds=CACHE_SEC):
        return _cache[1]
    loop = asyncio.get_running_loop()
    if _lock is None or _lock[0] is not loop:
        _lock = (loop, asyncio.Lock())
    async with _lock[1]:
        if not fresh and _cache and now - _cache[0] < timedelta(seconds=CACHE_SEC):
            return _cache[1]
        rules = [{"name": r.name, "enabled": r.enabled, "run": engine.runs[r.name].as_dict() if r.name in engine.runs else None}
                 for r in engine.config.rules]
        try:
            queue = await repository.delivery_queue(now)
            gave_up = await repository.count_gave_up(now - timedelta(hours=24))
        except Exception as exc:  # noqa: BLE001 - DB 에 물을 수 없으면 그것이 문제
            result = {"status": "down", "checked_at": now, "queue": [], "rules": {},
                      "problems": [{"level": "bad", "code": "db", "text": f"DB 에 물을 수 없습니다: {type(exc).__name__}", "n": 1}]}
        else:
            used = {n for r in engine.config.rules if r.enabled for n in r.notify}
            result = assess(engine.health_snapshot(), dispatcher.status(), queue, gave_up, rules, used, now)
            result["queue"] = queue
            result["rules"] = {r["name"]: r["state"] for r in rules}
        _cache = (now, result)
        return result

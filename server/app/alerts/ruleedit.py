"""화면의 규칙 편집기용: config/alerts.yaml 에서 규칙 한 개만 추가·수정·삭제·켜기/끄기.

파일 전체를 다시 쓰지 않고 해당 규칙 블록(`  - name: …` 부터 다음 규칙 직전까지)만 바꾼다.
→ 다른 규칙, 구역 제목 주석, 파일 머리말 설명이 그대로 남아서 사람이 직접 고치는 것과 섞어 써도 된다.
바꾼 결과는 호출하는 쪽(routers/alerts.py)이 rules.parse_text 로 전체 검증한 뒤에만 저장한다.

형식 가정 (config/alerts.yaml 과 같음):
  rules:
    # ---- 구역 제목 (들여쓰기 2칸 주석)
    - name: 규칙 이름        ← 규칙 시작 (들여쓰기 2칸 + "- ")
      키: 값                 ← 규칙 내용 (들여쓰기 4칸)
"""

from __future__ import annotations

import json
import re
from typing import Any

import yaml

# 파일에 쓰는 키 순서 (사람이 읽기 좋은 순서)
FIELD_ORDER = (
    "name", "sid", "group", "description", "kind", "enabled", "match", "group_by", "window", "threshold",
    "cooldown", "silent_for", "hosts", "severity", "tags", "notify",
)
SID_START = 1000001  # Snort 의 로컬 규칙 번호대처럼 100만 번대부터

_ITEM = re.compile(r"^  - ")
_SECTION = re.compile(r"^  #")
_PLAIN = re.compile(r"[0-9A-Za-z가-힣_][0-9A-Za-z가-힣_ .·()/\-]*")
_SPECIAL = re.compile(r"(?i)(true|false|yes|no|on|off|null|~|[+-]?[\d.]+([eE][+-]?\d+)?)")


class EditError(ValueError):
    """편집할 수 없는 상태 (규칙이 없음, 형식이 예상과 다름)."""


# ------------------------------------------------------------------ 쓰기
def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if _PLAIN.fullmatch(text) and not _SPECIAL.fullmatch(text) and text == text.strip():
        return text
    return json.dumps(text, ensure_ascii=False)  # JSON 문자열은 그대로 YAML 큰따옴표 문자열


def _flow_list(items: list[Any]) -> str:
    return "[" + ", ".join(_scalar(i) for i in items) + "]"


def _flow_map(mapping: dict[str, Any]) -> str:
    if not mapping:
        return "{}"
    # 조건 값은 숫자처럼 보여도 문자열이어야 하므로 항상 따옴표
    return "{ " + ", ".join(f"{_scalar(k)}: {json.dumps(str(v), ensure_ascii=False)}" for k, v in mapping.items()) + " }"


def emit_rule(rule: dict[str, Any]) -> str:
    """규칙 dict → 들여쓰기 2칸 목록 항목 텍스트 (끝에 줄바꿈 포함)."""
    unknown = set(rule) - set(FIELD_ORDER)
    if unknown:
        raise EditError(f"알 수 없는 항목: {sorted(unknown)}")
    lines = []
    for key in FIELD_ORDER:
        if key not in rule:
            continue
        value = rule[key]
        prefix = "  - " if not lines else "    "
        if key == "match":
            text = _flow_map(value)
        elif isinstance(value, (list, tuple)):
            text = _flow_list(list(value))
        else:
            text = _scalar(value)
        lines.append(f"{prefix}{key}: {text}")
    if not lines or not lines[0].startswith("  - name: "):
        raise EditError("규칙에는 name 이 있어야 합니다")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ 찾기
def _rules_span(lines: list[str]) -> tuple[int, int]:
    """rules: 줄 번호와 rules 구역이 끝나는 줄 번호(다음 최상위 키 또는 파일 끝)."""
    start = next((i for i, line in enumerate(lines) if re.match(r"^rules:\s*(#.*)?$", line)), None)
    if start is None:
        raise EditError("rules: 항목을 찾을 수 없습니다 (YAML 직접 편집을 쓰세요)")
    end = next((i for i in range(start + 1, len(lines))
                if lines[i] and not lines[i][0].isspace() and not lines[i].startswith("#")), len(lines))
    return start, end


def _blocks(lines: list[str]) -> list[tuple[int, int, dict]]:
    """규칙마다 (시작 줄, 끝 줄(포함하지 않음), 읽은 값). 끝의 빈 줄은 블록에 넣지 않는다."""
    start, end = _rules_span(lines)
    starts = [i for i in range(start + 1, end) if _ITEM.match(lines[i])]
    blocks = []
    for n, s in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else end
        # 다음 규칙 앞의 구역 제목 주석·빈 줄은 이 블록이 아니다
        for i in range(s + 1, e):
            if _SECTION.match(lines[i]):
                e = i
                break
        while e > s + 1 and not lines[e - 1].strip():
            e -= 1
        try:
            data = (yaml.safe_load("\n".join(lines[s:e])) or [None])[0]
        except yaml.YAMLError as exc:
            raise EditError(f"{s + 1}번째 줄 근처 YAML 오류: {exc}") from exc
        blocks.append((s, e, data if isinstance(data, dict) else {}))
    return blocks


def _find(lines: list[str], name: str) -> tuple[int, int, dict]:
    for block in _blocks(lines):
        if str(block[2].get("name", "")).strip() == name:
            return block
    raise EditError(f"규칙을 찾을 수 없습니다: {name}")


def names(text: str) -> list[str]:
    return [str(b[2].get("name", "")) for b in _blocks(text.split("\n"))]


def next_sid(text: str) -> int:
    sids = [b[2].get("sid") for b in _blocks(text.split("\n"))]
    sids = [s for s in sids if isinstance(s, int) and not isinstance(s, bool)]
    return max([SID_START - 1, *sids]) + 1


# ------------------------------------------------------------------ 바꾸기
def replace(text: str, name: str, rule: dict[str, Any]) -> str:
    lines = text.split("\n")
    s, e, _ = _find(lines, name)
    return "\n".join(lines[:s] + emit_rule(rule).rstrip("\n").split("\n") + lines[e:])


def append(text: str, rule: dict[str, Any]) -> str:
    """rules 구역의 끝(마지막 규칙 뒤)에 빈 줄 하나를 두고 추가."""
    text = re.sub(r"(?m)^rules:\s*\[\s*\]\s*$", "rules:", text)
    lines = text.split("\n")
    start, _ = _rules_span(lines)
    blocks = _blocks(lines)
    at = blocks[-1][1] if blocks else start + 1
    new = emit_rule(rule).rstrip("\n").split("\n")
    insert = ([""] if blocks else []) + new
    # 뒤에 다른 내용이 바로 붙지 않도록
    if at < len(lines) and lines[at].strip():
        insert.append("")
    return "\n".join(lines[:at] + insert + lines[at:])


def delete(text: str, name: str) -> str:
    lines = text.split("\n")
    s, e, _ = _find(lines, name)
    # 뒤따르는 빈 줄 하나도 함께 지워 간격을 유지
    if e < len(lines) and not lines[e].strip():
        e += 1
    return "\n".join(lines[:s] + lines[e:])


def set_enabled(text: str, name: str, enabled: bool) -> str:
    """켜기/끄기만 바꿀 때는 블록을 다시 쓰지 않고 enabled 줄만 고친다 (블록 안 주석 보존)."""
    lines = text.split("\n")
    s, e, _ = _find(lines, name)
    idx = next((i for i in range(s + 1, e) if re.match(r"^    enabled:", lines[i])), None)
    if enabled:
        if idx is not None:
            del lines[idx]
        return "\n".join(lines)
    if idx is not None:
        lines[idx] = "    enabled: false"
        return "\n".join(lines)
    # name / sid / group 다음에 넣는다
    at = s + 1
    while at < e and re.match(r"^    (sid|group|description):", lines[at]):
        at += 1
    lines.insert(at, "    enabled: false")
    return "\n".join(lines)

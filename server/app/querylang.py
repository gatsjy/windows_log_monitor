"""검색 문장(B-01, ADR-033): `event_id:4625 ip:10.0.0.5 -user:svc_backup level:오류,심각 "잘못된 암호"`

표준 라이브러리만 쓴다 — 개발 PC 에서 `python3 -I` 로도 import 해 web/js/querylang.js 와 교차 시험한다
(server/tests/js/crossfuzz.test.mjs). **web/js/querylang.js 와 한 줄씩 같은 알고리즘**이어야 한다:
규칙을 바꾸면 두 파일과 케이스 표(server/tests/querylang_cases.json)를 함께 고친다.
상수·오류 문구는 SYNC 하나에 두고, JS 파일의 @sync 블록과 같은지 pytest 가 확인한다(test_querylang_sync.py).

문법 요약 (docs/PROJECT.md §4.1)
- 띄어쓰기 = 그리고(AND), `키:a,b` = 그 키가 a 또는 b, 앞의 `-` = 제외, `"…"` = 메시지 구절, 그냥 단어 = 메시지 부분일치.
- 위치(start, end)는 코드 포인트 기준(0부터, end 미포함). 화면만 UTF-16 으로 바꾼다.
- 오류는 처음 하나만, 순서 고정: 길이 → 제어 문자 → 왼쪽부터 토큰(문법 → 키 → 값) → term 단위 개수 한도.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

# fmt: off
SYNC: dict[str, Any] = {
    "ws": [" ", "\t", "\n", "\r", "\u00a0", "\u3000"],
    "quotes": ["\"", "\u201c", "\u201d"],
    "reserved": {"*": "wildcard", "|": "pipe", "(": "paren", ")": "paren"},
    "reserved_words": ["AND", "OR", "NOT", "&&"],
    "keys": ["host", "channel", "provider", "source", "category", "user", "ip", "level", "event_id", "msg"],
    "time_keys": ["since", "until"],
    "levels": {"1": ["심각", "critical"], "2": ["오류", "error"], "3": ["경고", "warning"],
               "4": ["정보", "info", "information"], "5": ["상세", "verbose"]},
    "categories": ["security", "system", "application", "powershell", "defender", "rdp", "sysmon", "windows",
                   "iis", "mssql", "linux", "syslog", "file"],
    "category_hints": {"보안": "security", "시스템": "system", "응용": "application", "응용 프로그램": "application",
                       "app": "application", "파워셸": "powershell", "백신": "defender", "원격": "rdp",
                       "원격 데스크톱": "rdp", "기타": "windows", "웹": "iis", "웹 서버": "iis", "web": "iis",
                       "db": "mssql", "sql": "mssql", "리눅스": "linux", "장비": "syslog", "파일": "file"},
    "key_hints": {"q": "msg", "message": "msg", "text": "msg", "메시지": "msg", "내용": "msg",
                  "username": "user", "account": "user", "사용자": "user", "계정": "user",
                  "src_ip": "ip", "srcip": "ip", "source_ip": "ip", "ipaddress": "ip", "출발지": "ip", "아이피": "ip",
                  "eventid": "event_id", "event": "event_id", "id": "event_id", "eid": "event_id", "이벤트": "event_id",
                  "computer": "host", "pc": "host", "hostname": "host", "호스트": "host", "컴퓨터": "host",
                  "cat": "category", "분류": "category", "lvl": "level", "severity": "level", "수준": "level",
                  "레벨": "level", "채널": "channel", "공급자": "provider", "소스": "source",
                  "f": "f.경로", "field": "f.경로", "fields": "f.경로", "raw": "f.경로", "원본": "f.경로"},
    "limits": {"max_len": 500, "max_terms": 30, "max_values": 50, "max_value_len": 200, "max_fields": 10,
               "max_msg": 20, "max_segments": 16, "max_segment_len": 100, "max_event_id": 2147483647},
    "errors": {
        "too_long": "검색 문장은 {max}자까지 쓸 수 있습니다.",
        "control_char": "보이지 않는 제어 문자가 들어 있습니다. 지우고 다시 입력하세요.",
        "unterminated_quote": "따옴표가 닫히지 않았습니다. 끝에 \" 를 붙이세요.",
        "junk_after_quote": "닫는 따옴표 뒤에는 띄어쓰기나 쉼표가 와야 합니다.",
        "quote_in_word": "단어 중간에 따옴표가 있습니다. 전체를 따옴표로 감싸고, 안의 \" 는 \"\" 로 두 번 쓰세요.",
        "empty_quoted": "따옴표 안이 비어 있습니다.",
        "lone_minus": "'-' 뒤에 제외할 조건이나 단어를 붙여 쓰세요. 예) -user:svc_backup",
        "double_minus": "'-' 는 한 번만 씁니다. '-' 로 시작하는 글자를 찾으려면 따옴표로 감싸세요. 예) \"--force\"",
        "wildcard": "와일드카드(*)는 지원하지 않습니다(정확히 일치만). 글자 * 를 찾으려면 따옴표로 감싸세요.",
        "pipe": "'|' 는 쓸 수 없습니다. 여러 값 중 하나는 쉼표로 씁니다. 예) msg:timeout,refused · host:A,B",
        "paren": "괄호 묶음은 지원하지 않습니다. 글자 그대로 찾으려면 따옴표로 감싸세요.",
        "reserved_word": "'{word}' 는 쓸 수 없습니다. 띄어 쓰면 '그리고', 쉼표는 '또는'(host:A,B), 앞의 - 는 '제외'(-host:A)입니다. 글자 그대로 찾으려면 \"{word}\".",
        "operator": "비교·부정 기호 '{ch}' 는 쓸 수 없습니다. 제외는 -host:A 처럼 앞에 - 를 붙입니다.",
        "single_quote": "작은따옴표 대신 큰따옴표(\")로 감싸세요.",
        "missing_key": "':' 앞에 조건 이름이 없습니다. 글자 그대로 찾으려면 따옴표로 감싸세요.",
        "unknown_key": "알 수 없는 조건 '{key}' 입니다.{hint} 글자 그대로 찾으려면 따옴표로 감싸세요.",
        "hint_suggest": " '{suggest}' 를 찾으셨나요?",
        "time_key": "기간은 문장에 쓰지 않고 위의 기간 선택으로 정합니다.",
        "bad_path": "원본 필드 경로가 잘못되었습니다. 점으로 이어 씁니다. 예) f.EventData.LogonType",
        "bad_index": "배열 위치는 0, 1, 2 처럼 앞자리 0·부호 없이 씁니다.",
        "path_too_long": "원본 필드 경로가 너무 깁니다 (최대 {segments}단계, 단계마다 {segment}자).",
        "empty_value": "'{key}:' 뒤에 값이 없습니다.",
        "space_after_colon": "':' 뒤에 띄어쓰기가 있습니다. {key}:값 처럼 붙여 쓰세요.",
        "empty_item": "쉼표 앞뒤에 값이 없습니다.",
        "bad_level": "'{value}' 는 수준이 아닙니다. 심각·오류·경고·정보·상세 또는 1~5 중에서 씁니다.",
        "bad_int": "이벤트 ID '{value}' 는 0 이상의 정수여야 합니다. 여러 개는 4625,4740 처럼 씁니다.",
        "int_range": "이벤트 ID '{value}' 가 너무 큽니다 (최대 2147483647).",
        "bad_category": "'{value}' 는 분류 이름이 아닙니다.{hint} 쓸 수 있는 값: {list}",
        "cidr": "IP 대역(/) 검색은 지원하지 않습니다. 주소를 쉼표로 나열하세요.",
        "value_too_long": "값은 {max}자까지 쓸 수 있습니다.",
        "too_many_terms": "조건은 {max}개까지 쓸 수 있습니다.",
        "too_many_values": "한 조건의 값은 {max}개까지 쓸 수 있습니다.",
        "too_many_fields": "원본 필드(f.) 조건은 URL 의 f. 조건과 합쳐 {max}개까지 쓸 수 있습니다.",
        "too_many_msg": "메시지 단어·구절은 {max}개까지 쓸 수 있습니다.",
    },
}
# fmt: on

WS = frozenset(SYNC["ws"])
QUOTES = frozenset(SYNC["quotes"])
RESERVED: dict[str, str] = SYNC["reserved"]
RESERVED_WORDS = frozenset(SYNC["reserved_words"])
KEYS: list[str] = SYNC["keys"]
LIMITS: dict[str, int] = SYNC["limits"]
LEVEL_NAMES = {int(k): v[0] for k, v in SYNC["levels"].items()}           # 2 → '오류' (정규형 표기)
_LEVEL_OF = {name: int(k) for k, names in SYNC["levels"].items() for name in [k, *names]}
_IDENT = re.compile(r"[A-Za-z_가-힣][A-Za-z0-9_.가-힣-]*")
_INDEX_LIKE = re.compile(r"[+-]?[0-9]+")
_INDEX = re.compile(r"0|[1-9][0-9]*")
_DIGITS = re.compile(r"[0-9]+")
_TEMPLATE = re.compile(r"\{([a-z_]+)\}")
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _control(ch: str) -> bool:
    o = ord(ch)
    return (o < 0x20 and ch not in "\t\n\r") or o == 0x7F


def ascii_lower(text: str) -> str:
    """A-Z 만 소문자로 (str.lower 는 'İ' 같은 글자를 바꿔 JS 와 어긋난다)."""
    return text.translate(_ASCII_LOWER)


def fold(text: str) -> str:
    """메시지 대소문자 무시 비교용. PostgreSQL ILIKE(글자마다 towlower)와 맞춘다:
    Python·JS 의 lower 는 'Σ'(어말 시그마)와 'İ'(2글자로 바뀜)만 다르다. casefold 는 ß→ss 라 쓰지 않는다."""
    return text.replace("İ", "i").replace("Σ", "σ").lower()


def render_error(code: str, params: dict[str, Any]) -> str:
    return _TEMPLATE.sub(lambda m: str(params.get(m.group(1), "")), SYNC["errors"][code])


class FilterError(ValueError):
    """잘못된 필터 조건 (HTTP 400 으로 응답). filters.py 가 다시 내보낸다."""


class QueryError(FilterError):
    """검색 문장 오류: 어디(start~end, 코드 포인트)가 왜(code, 한국어 message) 틀렸는지."""

    def __init__(self, code: str, start: int, end: int, text: str, params: dict[str, Any] | None = None):
        self.code, self.start, self.end, self.text = code, start, end, text
        self.params = params or {}
        self.message = render_error(code, self.params)
        super().__init__(str(self))

    def __str__(self) -> str:
        snip = self.text[self.start:self.end][:20]
        where = f"검색 문장 {self.start + 1}번째 글자"
        return f"{where} '{snip}': {self.message}" if snip else f"{where}: {self.message}"

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "start": self.start, "end": self.end, "message": self.message}


@dataclass(frozen=True)
class Term:
    key: str                          # host channel provider source category user ip level event_id msg f
    values: tuple[Any, ...]           # level·event_id 는 int, category 는 코드, 나머지 문자열 (중복 제거·등장 순)
    neg: bool = False
    path: tuple[str, ...] = ()        # key == 'f' 일 때만
    span: tuple[int, int] = field(default=(0, 0), compare=False)   # '-' 포함 term 전체

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"key": self.key, "neg": self.neg, "values": list(self.values), "span": list(self.span)}
        if self.key == "f":
            out["path"] = list(self.path)
        return out


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _suggest(name: str, hints: dict[str, str], choices: list[str]) -> str:
    """오타 안내: 힌트 표(한글·흔한 영문 이름) 먼저, 그다음 3자 이상이면 편집 거리 2 이하 (동점이면 목록 순서)."""
    low = ascii_lower(name)
    if low in hints:
        return hints[low]
    if "." in low:
        head, rest = name.split(".", 1)
        found = hints.get(ascii_lower(head))
        if found == "f.경로":
            return "f." + rest
        if found:
            return found
    if len(low) >= 3:
        best, best_d = "", 3
        for choice in choices:
            d = _levenshtein(low, choice)
            if d < best_d:
                best, best_d = choice, d
        return best
    return ""


def _hint(suggest: str) -> str:
    return render_error("hint_suggest", {"suggest": suggest}) if suggest else ""


class _Scanner:
    def __init__(self, text: str, field_budget: int):
        self.t = text
        self.n = len(text)
        self.field_budget = field_budget
        self.n_msg = 0

    def err(self, code: str, start: int, end: int, **params: Any) -> QueryError:
        return QueryError(code, start, end, self.t, params)

    def count_msg(self, start: int, end: int) -> None:
        self.n_msg += 1
        if self.n_msg > LIMITS["max_msg"]:
            raise self.err("too_many_msg", start, end, max=LIMITS["max_msg"])

    def reserved(self, i: int) -> QueryError:
        return self.err(RESERVED[self.t[i]], i, i + 1)

    def parse(self) -> list[Term]:
        t, n = self.t, self.n
        if n > LIMITS["max_len"]:
            raise self.err("too_long", LIMITS["max_len"], n, max=LIMITS["max_len"])
        for i, ch in enumerate(t):
            if _control(ch):
                raise self.err("control_char", i, i + 1)
        terms: list[Term] = []
        n_fields = 0
        i = 0
        while True:
            while i < n and t[i] in WS:
                i += 1
            if i == n:
                break
            start, neg = i, False
            if t[i] == "-":
                if i + 1 == n or t[i + 1] in WS:
                    raise self.err("lone_minus", i, i + 1)
                if t[i + 1] == "-":
                    raise self.err("double_minus", i, i + 2)
                neg = True
                i += 1
            if t[i] in QUOTES:
                value, i = self.read_quoted(i)
                if i < n and t[i] not in WS:
                    raise self.err("junk_after_quote", i, i + 1)
                term = Term("msg", (value,), neg, (), (start, i))
                self.count_msg(start, i)
            else:
                term, i = self.read_bare_term(i, start, neg)
            if term.key == "f":
                n_fields += 1
                if n_fields > self.field_budget:
                    raise self.err("too_many_fields", *term.span, max=LIMITS["max_fields"])
            if len(terms) == LIMITS["max_terms"]:
                raise self.err("too_many_terms", *term.span, max=LIMITS["max_terms"])
            terms.append(term)
        return terms

    def read_bare_term(self, i: int, start: int, neg: bool) -> tuple[Term, int]:
        t, n = self.t, self.n
        if t[i] == "!":
            raise self.err("operator", i, i + 1, ch="!")
        if t[i] == "'":
            raise self.err("single_quote", i, i + 1)
        j = i
        while j < n and t[j] not in WS and t[j] not in QUOTES and t[j] != ":":
            if t[j] in RESERVED:
                raise self.reserved(j)
            j += 1
        if j < n and t[j] in QUOTES:
            raise self.err("quote_in_word", j, j + 1)
        if j == n or t[j] in WS:                                  # ':' 없는 단어 = 메시지 부분일치
            word = t[i:j]
            if word in RESERVED_WORDS:
                raise self.err("reserved_word", i, j, word=word)
            self.count_msg(start, j)
            return Term("msg", (word,), neg, (), (start, j)), j
        head = t[i:j]                                             # t[j] == ':'
        if head == "":
            raise self.err("missing_key", j, j + 1)
        low = ascii_lower(head)
        if low in KEYS:
            return self.read_values(low, (), head, j, start, neg)
        if low.startswith("f."):
            path = self.parse_path(head[2:], i + 2, (i, j))
            return self.read_values("f", path, head, j, start, neg)
        if low in SYNC["time_keys"]:
            raise self.err("time_key", i, j)
        nxt = t[j + 1] if j + 1 < n else ""
        if _IDENT.fullmatch(head) and nxt not in (":", "\\", "/"):
            suggested = _suggest(head, SYNC["key_hints"], KEYS)       # suggest: 화면의 '고치기' 단추용 (문구에는 hint)
            raise self.err("unknown_key", i, j, key=head, hint=_hint(suggested), suggest=suggested)
        k = j                                                     # ':' 가 든 메시지 단어 (C:\x, http://x, 12:30, fe80::1)
        while k < n and t[k] not in WS:
            if t[k] in QUOTES:
                raise self.err("quote_in_word", k, k + 1)
            if t[k] in RESERVED:
                raise self.reserved(k)
            k += 1
        self.count_msg(start, k)
        return Term("msg", (t[i:k],), neg, (), (start, k)), k

    def parse_path(self, s: str, off: int, key_span: tuple[int, int]) -> tuple[str, ...]:
        segs = s.split(".")
        if s == "" or "" in segs or "," in s:
            raise self.err("bad_path", *key_span)
        if len(segs) > LIMITS["max_segments"] or any(len(seg) > LIMITS["max_segment_len"] for seg in segs):
            raise self.err("path_too_long", *key_span, segments=LIMITS["max_segments"], segment=LIMITS["max_segment_len"])
        pos = off
        for seg in segs:
            if _INDEX_LIKE.fullmatch(seg) and not _INDEX.fullmatch(seg):
                raise self.err("bad_index", pos, pos + len(seg))
            pos += len(seg) + 1
        return tuple(segs)

    def read_values(self, key: str, path: tuple[str, ...], head: str, j: int, start: int,
                    neg: bool) -> tuple[Term, int]:
        t, n = self.t, self.n
        k = j + 1
        if k == n:
            raise self.err("empty_value", j, j + 1, key=head)
        if t[k] in WS:
            m = k
            while m < n and t[m] in WS:
                m += 1
            if m == n:
                raise self.err("empty_value", j, j + 1, key=head)
            raise self.err("space_after_colon", j, m, key=head)
        values: list[Any] = []
        while True:
            if t[k] in QUOTES:
                value, e = self.read_quoted(k)
                s0, s1 = k, e
                if e < n and t[e] not in WS and t[e] != ",":
                    raise self.err("junk_after_quote", e, e + 1)
            elif t[k] == ",":
                raise self.err("empty_item", k, k + 1)
            else:
                e = k
                while e < n and t[e] not in WS and t[e] != ",":
                    if t[e] in QUOTES:
                        raise self.err("quote_in_word", e, e + 1)
                    if t[e] in RESERVED:
                        raise self.reserved(e)
                    e += 1
                value = t[k:e]
                s0, s1 = k, e
                if value[0] in "<>=!":
                    raise self.err("operator", k, k + 1, ch=value[0])
                if value[0] == "'":
                    raise self.err("single_quote", k, k + 1)
            if len(value) > LIMITS["max_value_len"]:
                raise self.err("value_too_long", s0, s1, max=LIMITS["max_value_len"])
            typed = self.validate(key, value, s0, s1)
            if typed not in values:
                if len(values) == LIMITS["max_values"]:
                    raise self.err("too_many_values", s0, s1, max=LIMITS["max_values"])
                values.append(typed)
            if key == "msg":
                self.count_msg(s0, s1)
            k = e
            if k < n and t[k] == ",":
                if k + 1 == n or t[k + 1] in WS:
                    raise self.err("empty_item", k, k + 1)
                k += 1
                continue
            break
        return Term(key, tuple(values), neg, path, (start, k)), k

    def read_quoted(self, p: int) -> tuple[str, int]:
        t, n = self.t, self.n
        k = p + 1
        buf: list[str] = []
        while True:
            if k == n:
                raise self.err("unterminated_quote", p, n)
            c = t[k]
            if c in QUOTES:
                if k + 1 < n and t[k + 1] in QUOTES:             # "" → " (스마트 따옴표도 같은 규칙)
                    buf.append(c)
                    k += 2
                    continue
                k += 1
                break
            buf.append(c)
            k += 1
        value = "".join(buf)
        if all(c in WS for c in value):
            raise self.err("empty_quoted", p, k)
        return value, k

    def validate(self, key: str, value: str, s0: int, s1: int) -> Any:
        if key == "ip" and "/" in value:
            raise self.err("cidr", s0, s1)
        if key == "category":
            low = ascii_lower(value)
            if low in SYNC["categories"]:
                return low
            suggested = _suggest(value, SYNC["category_hints"], SYNC["categories"])
            raise self.err("bad_category", s0, s1, value=value, hint=_hint(suggested), suggest=suggested,
                           list=", ".join(SYNC["categories"]))
        if key == "level":
            level = _LEVEL_OF.get(ascii_lower(value))
            if level is None:
                raise self.err("bad_level", s0, s1, value=value)
            return level
        if key == "event_id":
            if not _DIGITS.fullmatch(value):
                raise self.err("bad_int", s0, s1, value=value)
            digits = value.lstrip("0") or "0"
            if len(digits) > 10 or int(digits) > LIMITS["max_event_id"]:
                raise self.err("int_range", s0, s1, value=value)
            return int(digits)
        return value


def parse_terms(text: str, *, field_budget: int = LIMITS["max_fields"]) -> list[Term]:
    """문장 → Term 목록. 틀리면 QueryError(처음 하나)."""
    return _Scanner(text, field_budget).parse()


# --------------------------------------------------------------------- 정규형

def _needs_quote(value: str, kind: str) -> bool:
    if value == "" or any(c in WS or c in QUOTES or c in RESERVED or _control(c) for c in value):
        return True
    if value[0] in "!'":
        return True
    if kind == "word":
        return value[0] == "-" or ":" in value or value in RESERVED_WORDS
    return value[0] in "<>=" or "," in value


def format_value(value: Any, kind: str = "value") -> str:
    """값 하나 → 문장 표기. kind = 'word'(메시지 단어) | 'value'(키:값의 값)."""
    text = str(value)
    if not _needs_quote(text, kind):
        return text
    return '"' + "".join(c + c if c in QUOTES else c for c in text) + '"'


def format_term(term: Term) -> str:
    sign = "-" if term.neg else ""
    if term.key == "msg" and len(term.values) == 1:
        return sign + format_value(term.values[0], "word")
    if term.key == "level":
        values = [LEVEL_NAMES[v] for v in term.values]
    else:
        values = [format_value(v) for v in term.values]
    key = "f." + ".".join(term.path) if term.key == "f" else term.key
    return f"{sign}{key}:{','.join(values)}"


def format_query(terms: list[Term]) -> str:
    return " ".join(format_term(t) for t in terms)


# --------------------------------------------------------------------- 원본 JSON

def _number_text(value: float) -> str:
    """실수 → PostgreSQL numeric 출력 (지수 표기 없음). 저장할 때 json.dumps(=repr)가 그대로 jsonb 숫자가 되므로
    repr 의 자릿수를 지수 없이 펼치면 #>> 와 같다: 1e-05 → 0.00001, 1e+21 → 1000…0, 1000.0 → 1000.0."""
    text = format(Decimal(repr(value)), "f")
    return text[1:] if text.startswith("-") and Decimal(text) == 0 else text   # numeric 에는 -0 이 없다


def _jsonb_text(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return _number_text(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(_jsonb_text(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{json.dumps(str(k), ensure_ascii=False)}: {_jsonb_text(v)}" for k, v in value.items()) + "}"
    return json.dumps(value, ensure_ascii=False, default=str)


def raw_text(value: Any) -> str:
    """PostgreSQL `raw #>> path` 와 같은 문자열 표현 (배열·객체는 ', ' · ': ' 구분자, 실수는 지수 표기 없이)."""
    return value if isinstance(value, str) else _jsonb_text(value)


def walk_raw(value: Any, path: list[str] | tuple[str, ...]) -> Any:
    """원본 JSON 에서 경로 값 (없으면 None). 배열은 ASCII 숫자 위치만 ('²'.isdigit() 가 True 라 isascii 도 본다)."""
    for part in path:
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, list) and part.isascii() and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return None
    return value

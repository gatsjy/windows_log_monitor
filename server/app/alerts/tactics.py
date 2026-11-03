"""MITRE ATT&CK 전술 (BACKLOG B-67 2단계, ADR-065): 규칙 태그의 기법(`MITRE T1110.001`)·전술(`MITRE TA0006`) → 전술.

상관 알림(kind: correlation)이 '같은 개체에서 서로 다른 전술 N개'를 셀 때 쓴다. 표는 기본 규칙이 쓰는 기법과 Windows 로그로 흔히
잡는 기법만 — ATT&CK Enterprise 의 기법 → 전술 대응(기법 하나가 여러 전술에 속할 수 있다)을 그대로 옮겼다. 하위 기법이 표에 없으면
상위 기법으로 본다(T1110.003 → T1110). 표에 없는 기법은 전술이 없다(규칙 표·미리보기에 '전술을 모르는 태그'로 보인다).

서로 다른 전술 수는 **규칙과 전술의 최대 짝짓기**로 센다 — 규칙 하나는 전술 하나로만 센다. 여러 전술에 속한 기법 하나
(T1078 유효한 계정 = 초기 접근·지속·권한 상승·방어 회피)가 혼자 '전술 3개'가 되지 않게, 같은 규칙이 여러 번 울려도 한 번으로.
"""

from __future__ import annotations

import re

# 전술 번호 → 한국어 이름 (ATT&CK Enterprise 의 14개, 공격 흐름 순서)
TACTICS: dict[str, str] = {
    "TA0043": "정찰", "TA0042": "자원 개발", "TA0001": "초기 접근", "TA0002": "실행", "TA0003": "지속",
    "TA0004": "권한 상승", "TA0005": "방어 회피", "TA0006": "자격 증명 접근", "TA0007": "탐색", "TA0008": "내부 이동",
    "TA0009": "수집", "TA0011": "명령·제어", "TA0010": "유출", "TA0040": "영향",
}
ORDER = {t: i for i, t in enumerate(TACTICS)}

IA, EX, PE, PR, DE, CA, DI, LM, CO, C2, EF, IM = ("TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007",
                                                  "TA0008", "TA0009", "TA0011", "TA0010", "TA0040")
# 기법 → 전술 (PE = 지속, PR = 권한 상승)
TECHNIQUES: dict[str, tuple[str, ...]] = {
    "T1003": (CA,), "T1005": (CO,), "T1016": (DI,), "T1018": (DI,), "T1021": (LM,), "T1027": (DE,), "T1036": (DE,),
    "T1037": (PE, PR), "T1039": (CO,), "T1041": (EF,), "T1046": (DI,), "T1047": (EX,), "T1048": (EF,), "T1049": (DI,),
    "T1053": (EX, PE, PR), "T1055": (DE, PR), "T1057": (DI,), "T1059": (EX,), "T1069": (DI,), "T1070": (DE,), "T1071": (C2,),
    "T1074": (CO,), "T1078": (DE, PE, PR, IA), "T1082": (DI,), "T1083": (DI,), "T1087": (DI,), "T1090": (C2,),
    "T1095": (C2,), "T1098": (PE, PR), "T1102": (C2,), "T1105": (C2,), "T1110": (CA,), "T1112": (DE,), "T1113": (CO,),
    "T1119": (CO,), "T1133": (PE, IA), "T1134": (DE, PR), "T1135": (DI,), "T1136": (PE,), "T1190": (IA,), "T1201": (DI,),
    "T1204": (EX,), "T1207": (DE,), "T1210": (LM,), "T1218": (DE,), "T1219": (C2,), "T1482": (DI,), "T1484": (DE, PR),
    "T1485": (IM,), "T1486": (IM,), "T1489": (IM,), "T1490": (IM,), "T1505": (PE,), "T1529": (IM,), "T1531": (IM,),
    "T1543": (PE, PR), "T1546": (PR, PE), "T1547": (PE, PR), "T1548": (PR, DE), "T1550": (DE, LM), "T1552": (CA,),
    "T1555": (CA,), "T1556": (CA, DE, PE), "T1558": (CA,), "T1560": (CO,), "T1562": (DE,), "T1566": (IA,), "T1567": (EF,),
    "T1569": (EX,), "T1570": (LM,), "T1571": (C2,), "T1572": (C2,), "T1574": (PE, PR, DE), "T1012": (DI,),
}
_TAG = re.compile(r"^MITRE\s+(TA\d{4}|T\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def of_tag(tag: str) -> tuple[str, ...] | None:
    """태그 하나 → 전술들. MITRE 태그가 아니면 None, MITRE 인데 표에 없는 기법이면 ()."""
    m = _TAG.match(" ".join(str(tag).split()))
    if not m:
        return None
    code = m.group(1).upper()
    if code.startswith("TA"):
        return (code,) if code in TACTICS else ()
    return TECHNIQUES.get(code) or TECHNIQUES.get(code.split(".", 1)[0], ())


def of_tags(tags: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    """규칙 태그들 → 그 규칙의 전술(겹침 없이, 흐름 순서)."""
    found = {t for tag in tags for t in (of_tag(tag) or ())}
    return tuple(sorted(found, key=ORDER.__getitem__))


def unknown_tags(tags: list[str] | tuple[str, ...]) -> list[str]:
    """MITRE 태그인데 전술을 모르는 것 — 상관 알림에 들지 않으니 규칙 표·미리보기에 보인다."""
    return [t for t in tags if of_tag(t) == ()]


def label(tactic: str) -> str:
    return TACTICS.get(tactic, tactic)


def assign(rule_tactics: dict[str, tuple[str, ...]]) -> dict[str, str]:
    """규칙 → 전술 하나씩 (최대 짝짓기, 규칙마다 다른 전술). 돌려준 개수가 '서로 다른 전술 수'.
    규칙·전술은 많아야 수십 개라 증가 경로(Kuhn)로 충분하다. 규칙은 이름 순·전술은 흐름 순으로 시도해 결과가 늘 같다."""
    owner: dict[str, str] = {}   # 전술 → 규칙

    def place(rule: str, seen: set[str]) -> bool:
        for tactic in rule_tactics[rule]:
            if tactic in seen:
                continue
            seen.add(tactic)
            if tactic not in owner or place(owner[tactic], seen):
                owner[tactic] = rule
                return True
        return False

    for rule in sorted(rule_tactics):
        place(rule, set())
    return {rule: tactic for tactic, rule in owner.items()}

"""판정 결과 타입과 공통 도우미."""

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from modules.parser.log_parser import ParsedLog, Section

Status = Literal["good", "vulnerable", "na"]


@dataclass(frozen=True)
class Judgement:
    status: Status
    reason: str


@dataclass(frozen=True)
class Rule:
    item_code: str
    section: str
    judge: Callable[[Section, ParsedLog], Judgement]


EXPLICIT_RESULT = re.compile(
    r"^(?:RESULT=(OK|VULNERABLE|N/A)|STATUS:\s*(GOOD|VULNERABLE|NA)|\[(양호|취약|해당없음)\])\s*$",
    re.IGNORECASE,
)
_EXPLICIT_MAP: dict[str, Status] = {
    "ok": "good",
    "good": "good",
    "양호": "good",
    "vulnerable": "vulnerable",
    "취약": "vulnerable",
    "n/a": "na",
    "na": "na",
    "해당없음": "na",
}


def explicit_result(section: Section) -> Judgement | None:
    """구간 안에 결과가 명시되어 있으면(RESULT=OK 등) 그 값을 우선 쓴다."""
    for line in section.lines:
        match = EXPLICIT_RESULT.match(line.strip())
        if match:
            value = next(group for group in match.groups() if group)
            return Judgement(
                _EXPLICIT_MAP[value.lower()], f"스크립트가 결과를 명시함: {line.strip()}"
            )
    return None


def good(reason: str) -> Judgement:
    return Judgement("good", reason)


def vulnerable(reason: str) -> Judgement:
    return Judgement("vulnerable", reason)


def na(reason: str) -> Judgement:
    return Judgement("na", reason)


def int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None

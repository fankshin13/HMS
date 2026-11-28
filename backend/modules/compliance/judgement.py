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
    # 이 항목을 수집하기 시작한 스크립트 버전.
    # 더 오래된 스크립트 결과에는 구간이 없으므로 판정하지 않는다.
    since: tuple[int, ...] = (1, 0, 0)


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


# --- 공통 수집 형식 해석 (표준 스크립트의 KEY=값 줄) -------------------------------------------

_KV = re.compile(r"([A-Z_]+)=(\S*)")


def kv(line: str) -> dict[str, str]:
    """'A=1 B=2' 형태 줄을 사전으로. 같은 키는 처음 값을 쓴다."""
    result: dict[str, str] = {}
    for key, value in _KV.findall(line):
        result.setdefault(key, value)
    return result


@dataclass(frozen=True)
class FileStat:
    path: str
    owner: str
    group: str
    mode: int
    fields: dict[str, str]

    @property
    def mode_text(self) -> str:
        return f"{self.mode:o}"


def file_stats(lines: list[str], prefix: str = "") -> list[FileStat]:
    """stat 출력(FILE= OWNER= GROUP= MODE=) 줄을 해석한다.

    prefix 가 있으면 그 문자열로 시작하는 줄만 본다.
    """
    stats: list[FileStat] = []
    for line in lines:
        if prefix and not line.startswith(prefix):
            continue
        fields = kv(line)
        if {"FILE", "OWNER", "MODE"} <= fields.keys() and re.fullmatch(
            r"[0-7]{1,4}", fields["MODE"]
        ):
            stats.append(
                FileStat(
                    fields["FILE"],
                    fields["OWNER"],
                    fields.get("GROUP", ""),
                    int(fields["MODE"], 8),
                    fields,
                )
            )
    return stats


def exceeds(mode: int, limit: int) -> bool:
    """권한(특수 비트 포함)이 limit 에 없는 비트를 가지면 True."""
    return mode & 0o7777 & ~limit != 0


def active_services(section: Section) -> list[str]:
    """실행 중(active)이거나 자동 시작(enabled)인 SERVICE=, 그리고 PROCESS= 로 확인된 프로세스."""
    found: list[str] = []
    for line in section.lines:
        fields = kv(line)
        if "SERVICE" in fields and (
            fields.get("ACTIVE") == "active" or fields.get("ENABLED") == "enabled"
        ):
            found.append(fields["SERVICE"])
    found.extend(section.values("PROCESS"))
    return found


def inet_enabled(section: Section) -> list[str]:
    return section.values("INETD_ENABLED") + section.values("XINETD_ENABLED")


def listening_ports(section: Section) -> set[int]:
    ports: set[int] = set()
    for value in section.values("LISTEN"):
        port = value.rsplit(":", 1)[-1]
        if port.isdigit():
            ports.add(int(port))
    return ports

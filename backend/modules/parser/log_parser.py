"""표준 점검 스크립트 결과 텍스트를 구간(항목) 단위로 나누는 순수 파서.

입력 규격 (frontend/public/scripts/kisa_check_*.{sh,bat} 출력):
    [START] OS=<Linux|Windows> HOSTNAME=<호스트명> DATE=... SCRIPT=... VERSION=...
    [INFO] KEY=VALUE
    ==== <구간> BEGIN ====
    ...명령과 출력...
    ==== <구간> END ====
    [END]

어떤 입력에도 예외를 던지지 않는다. 구조를 해석할 수 없는 줄은 error_lines 에 줄 번호와 함께 담는다.
"""

import re
from dataclasses import dataclass, field
from typing import Literal

OsType = Literal["linux", "windows"]

START = re.compile(
    r"^\[START\] OS=(Linux|Windows) HOSTNAME=([A-Za-z0-9][A-Za-z0-9._-]{0,254})(?:\s|$)"
)
INFO = re.compile(r"^\[INFO\] ([A-Z_]+)=(.*)$")
SECTION = re.compile(r"^==== (\S+) (BEGIN|END) ====$")
COMMAND_PREFIX = "$ "
MAX_SNIPPET_CHARS = 2000


@dataclass(frozen=True)
class ErrorLine:
    line_number: int
    reason: str
    raw_snippet: str


@dataclass
class Section:
    name: str
    start_line: int
    end_line: int
    lines: list[str] = field(default_factory=list)

    def text(self) -> str:
        return "\n".join(self.lines)

    def snippet(self) -> str:
        text = self.text()
        return text if len(text) <= MAX_SNIPPET_CHARS else text[:MAX_SNIPPET_CHARS] + "\n…(생략)"

    def command_output(self, command_fragment: str) -> list[str] | None:
        """'$ <명령>' 줄 중 command_fragment 를 포함하는 첫 명령의 출력 줄들. 명령이 없으면 None."""
        for index, line in enumerate(self.lines):
            if line.startswith(COMMAND_PREFIX) and command_fragment in line:
                output: list[str] = []
                for following in self.lines[index + 1 :]:
                    if following.startswith(COMMAND_PREFIX) or following.startswith("NOT_FOUND="):
                        break
                    output.append(following)
                return output
        return None

    def values(self, key: str) -> list[str]:
        """'KEY=값' 형태(줄 시작 또는 공백 뒤)의 값 목록. 값은 다음 공백 전까지."""
        pattern = re.compile(rf"(?:^|\s){re.escape(key)}=(\S*)")
        return [match.group(1) for line in self.lines for match in pattern.finditer(line)]


@dataclass
class ParsedLog:
    os_type: OsType | None
    hostname: str | None
    info: dict[str, list[str]]
    sections: dict[str, Section]
    error_lines: list[ErrorLine]
    has_end: bool


def _error(number: int, reason: str, line: str) -> ErrorLine:
    return ErrorLine(number, reason, line[:200])


def parse_log(text: str) -> ParsedLog:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    parsed = ParsedLog(
        os_type=None, hostname=None, info={}, sections={}, error_lines=[], has_end=False
    )
    current: Section | None = None

    for number, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        marker = SECTION.match(line.strip())

        if current is not None:
            if marker and marker.group(2) == "END" and marker.group(1) == current.name:
                current.end_line = number
                if current.name in parsed.sections:
                    parsed.error_lines.append(
                        _error(current.start_line, f"{current.name} 구간이 중복되었습니다", line)
                    )
                else:
                    parsed.sections[current.name] = current
                current = None
            elif marker:
                parsed.error_lines.append(
                    _error(
                        number, f"{current.name} 구간이 닫히기 전에 새 구분 표시가 나왔습니다", line
                    )
                )
                current = (
                    Section(marker.group(1), number, number) if marker.group(2) == "BEGIN" else None
                )
            elif "\x00" in line:
                parsed.error_lines.append(
                    _error(number, "텍스트가 아닌 데이터가 섞여 있습니다", line.replace("\x00", ""))
                )
            else:
                current.lines.append(line)
            continue

        if not line.strip():
            continue
        if marker and marker.group(2) == "BEGIN":
            current = Section(marker.group(1), number, number)
        elif marker:
            parsed.error_lines.append(_error(number, "짝이 없는 구간 종료 표시입니다", line))
        elif start := START.match(line):
            if parsed.hostname is not None:
                parsed.error_lines.append(
                    _error(number, "시작 표시([START])가 중복되었습니다", line)
                )
            else:
                parsed.os_type = "windows" if start.group(1) == "Windows" else "linux"
                parsed.hostname = start.group(2)
        elif info := INFO.match(line):
            parsed.info.setdefault(info.group(1), []).append(info.group(2).strip())
        elif line.strip() == "[END]":
            parsed.has_end = True
        else:
            parsed.error_lines.append(_error(number, "표준 형식이 아닌 줄입니다", line))

    if current is not None:
        parsed.error_lines.append(
            _error(current.start_line, f"{current.name} 구간이 닫히지 않았습니다", "")
        )
    if parsed.hostname is None:
        parsed.error_lines.insert(
            0,
            _error(
                1, "표준 스크립트의 시작 표시([START])를 찾지 못했습니다", lines[0] if lines else ""
            ),
        )
    if not parsed.has_end:
        parsed.error_lines.append(
            _error(len(lines), "결과 파일이 끝까지 저장되지 않았습니다([END] 없음)", "")
        )
    return parsed

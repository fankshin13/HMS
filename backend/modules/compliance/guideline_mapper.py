"""파싱한 로그를 KISA 항목별 판정 결과로 바꾼다.

결함이 있는 부분만 격리하고 나머지는 모두 판정한다.
"""

from dataclasses import dataclass, field

from modules.compliance.judgement import Rule, Status, explicit_result
from modules.compliance.kisa_linux import LINUX_RULES
from modules.compliance.kisa_windows import WINDOWS_RULES
from modules.parser.log_parser import ErrorLine, ParsedLog

RULES: dict[str, list[Rule]] = {"linux": LINUX_RULES, "windows": WINDOWS_RULES}


@dataclass(frozen=True)
class ItemResult:
    item_code: str
    status: Status
    reason: str
    stdout_snippet: str
    start_line: int
    end_line: int


@dataclass
class MappedLog:
    results: list[ItemResult] = field(default_factory=list)
    errors: list[ErrorLine] = field(default_factory=list)

    @property
    def quarantined(self) -> bool:
        return bool(self.errors)


def map_log(log: ParsedLog) -> MappedLog:
    mapped = MappedLog(errors=list(log.error_lines))
    if log.os_type is None:
        return mapped

    for rule in RULES[log.os_type]:
        section = log.sections.get(rule.section)
        if section is None:
            mapped.errors.append(
                ErrorLine(0, f"{rule.item_code} 판정에 필요한 {rule.section} 구간이 없습니다", "")
            )
            continue
        try:
            judgement = explicit_result(section) or rule.judge(section, log)
        except Exception as exc:
            # 규칙 하나의 결함이 다른 항목 판정을 막지 않도록, 숨기지 않고 격리 목록에 기록한다
            mapped.errors.append(
                ErrorLine(
                    section.start_line, f"{rule.item_code} 판정 중 오류: {type(exc).__name__}", ""
                )
            )
            continue
        mapped.results.append(
            ItemResult(
                item_code=rule.item_code,
                status=judgement.status,
                reason=judgement.reason,
                stdout_snippet=f"[판정 근거] {judgement.reason}\n{section.snippet()}",
                start_line=section.start_line,
                end_line=section.end_line,
            )
        )
    return mapped

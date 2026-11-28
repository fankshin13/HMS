"""KISA 2026 상세가이드 Windows 서버 항목 판정 규칙.

표준 스크립트 kisa_check_windows.bat 출력 기준.
"""

import re

from modules.compliance.judgement import Judgement, Rule, good, int_or_none, vulnerable
from modules.compliance.kisa_windows_high import HIGH_RULES
from modules.compliance.kisa_windows_medium import MEDIUM_LOW_RULES
from modules.parser.log_parser import ParsedLog, Section

_ACCOUNT = re.compile(r"ACCOUNT=(\S+) ENABLED=(True|False) RID=(\d+)")


def _account_by_rid(section: Section, rid: str) -> tuple[str, bool] | None:
    for line in section.lines:
        match = _ACCOUNT.search(line)
        if match and match.group(3) == rid:
            return match.group(1), match.group(2) == "True"
    return None


def _policy(log: ParsedLog, key: str) -> str | None:
    section = log.sections.get("WIN-SECURITY_POLICY")
    if section is None:
        return None
    for line in section.lines:
        match = re.match(rf"^\s*{re.escape(key)}\s*=\s*(.*)$", line)
        if match:
            return match.group(1).strip().strip('"')
    return None


def w01(section: Section, _: ParsedLog) -> Judgement:
    account = _account_by_rid(section, "500")
    if account is None:
        return vulnerable("기본 관리자 계정(RID 500)을 확인하지 못했습니다(수동 확인 필요)")
    name, _enabled = account
    if name.lower() == "administrator":
        return vulnerable("기본 관리자 계정 이름이 Administrator 그대로입니다")
    return good("기본 관리자 계정 이름이 변경되어 있습니다")


def w02(section: Section, _: ParsedLog) -> Judgement:
    account = _account_by_rid(section, "501")
    if account is None:
        return vulnerable("Guest 계정(RID 501)을 확인하지 못했습니다(수동 확인 필요)")
    if account[1]:
        return vulnerable("Guest 계정이 활성화되어 있습니다")
    return good("Guest 계정이 비활성화되어 있습니다")


def w04(section: Section, log: ParsedLog) -> Judgement:
    threshold = int_or_none(_policy(log, "LockoutBadCount"))
    if threshold is None:
        match = re.search(r"Lockout threshold:\s*(\S+)", section.text())
        threshold = (
            0
            if match and match.group(1).lower() == "never"
            else int_or_none(match.group(1) if match else None)
        )
    if threshold is None:
        return vulnerable("계정 잠금 임계값을 확인하지 못했습니다(수동 확인 필요)")
    if 1 <= threshold <= 5:
        return good(f"계정 잠금 임계값이 {threshold}회로 설정되어 있습니다")
    return vulnerable(
        "계정 잠금 임계값이 설정되지 않았습니다"
        if threshold == 0
        else f"계정 잠금 임계값이 {threshold}회로 기준(5회 이하)을 벗어납니다"
    )


def w05(section: Section, _: ParsedLog) -> Judgement:
    value = None
    for line in section.lines:
        match = re.match(r"^\s*ClearTextPassword\s*=\s*(\d+)", line)
        if match:
            value = int(match.group(1))
    if value is None:
        return vulnerable(
            "'해독 가능한 암호화를 사용하여 암호 저장' 정책을 확인하지 못했습니다(수동 확인 필요)"
        )
    if value == 0:
        return good("'해독 가능한 암호화를 사용하여 암호 저장' 정책이 사용 안 함입니다")
    return vulnerable("'해독 가능한 암호화를 사용하여 암호 저장' 정책이 사용으로 되어 있습니다")


_BASE_RULES: list[Rule] = [
    Rule("W-01", "WIN-LOCAL_USERS", w01),
    Rule("W-02", "WIN-LOCAL_USERS", w02),
    Rule("W-04", "WIN-ACCOUNT_POLICY", w04),
    Rule("W-05", "WIN-SECURITY_POLICY", w05),
]


WINDOWS_RULES: list[Rule] = sorted(
    _BASE_RULES + HIGH_RULES + MEDIUM_LOW_RULES, key=lambda rule: int(rule.item_code.split("-")[1])
)

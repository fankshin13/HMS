"""KISA 2026 상세가이드 Unix 서버 항목 판정 규칙 (표준 스크립트 kisa_check_linux.sh v1.1 출력 기준).

근거가 부족해 자동으로 확정할 수 없으면 보수적으로 '취약'으로 판정하고 사유를 남긴다.
(수동 판정 변경으로 해소한다.)
"""

import re

from modules.compliance.judgement import Judgement, Rule, good, int_or_none, na, vulnerable
from modules.parser.log_parser import ParsedLog, Section

_MODE = re.compile(r"OWNER=(\S+) MODE=([0-7]{1,4})\b")


def _active(lines: list[str] | None) -> bool:
    return any(line.strip() == "active" for line in lines or [])


def _enabled_units(lines: list[str] | None) -> list[str]:
    return [line for line in lines or [] if re.search(r"\benabled\b", line)]


def _listening(lines: list[str] | None) -> bool:
    return any(line.strip() for line in lines or [])


def u01(section: Section, _: ParsedLog) -> Judgement:
    sshd = section.command_output("permitrootlogin") or []
    values = [
        line.split()[-1].lower() for line in sshd if line.lower().startswith("permitrootlogin")
    ]
    telnet_active = _active(section.command_output("telnet.socket"))
    securetty_pts = [
        line for line in section.command_output("/etc/securetty") or [] if line.startswith("pts")
    ]

    if telnet_active and securetty_pts:
        return vulnerable(
            "Telnet 이 사용 중이며 /etc/securetty 에 pts 항목이 있어 root 원격 접속이 허용됩니다"
        )
    if values and values[0] != "no":
        return vulnerable(f"SSH PermitRootLogin 값이 '{values[0]}' 입니다 (no 여야 함)")
    if values:
        return good("SSH PermitRootLogin no 로 root 직접 접속이 차단되어 있습니다")
    if "NOT_FOUND=/etc/ssh/sshd_config" in section.lines and not telnet_active:
        return good("원격 터미널 서비스(SSH·Telnet)를 사용하지 않습니다")
    return vulnerable("SSH root 접속 설정을 확인하지 못했습니다(수동 확인 필요)")


def u02(section: Section, _: ParsedLog) -> Judgement:
    """비밀번호 관리정책.

    영문·숫자·특수문자 포함 8자 이상, 최소 사용 1일, 최대 사용 90일, 최근 비밀번호 4회 기억.
    """
    settings: dict[str, int] = {}
    for line in section.lines:
        for key, value in re.findall(
            r"\b(minlen|minclass|dcredit|ucredit|lcredit|ocredit|remember)\s*=\s*(-?\d+)", line
        ):
            settings.setdefault(key, int(value))
    login_defs = dict(
        re.findall(r"^PASS_(MIN_DAYS|MAX_DAYS)\s+(\d+)", section.text(), re.MULTILINE)
    )
    pwquality_used = "minlen" in settings or any(
        line for line in section.command_output("pam_pwquality") or [] if line.strip()
    )

    missing: list[str] = []
    has_alpha = settings.get("ucredit", 0) < 0 or settings.get("lcredit", 0) < 0
    has_digit = settings.get("dcredit", 0) < 0
    has_special = settings.get("ocredit", 0) < 0
    if not (settings.get("minclass", 0) >= 4 or (has_alpha and has_digit and has_special)):
        missing.append("영문·숫자·특수문자 조합")
    if not pwquality_used or settings.get("minlen", 8) < 8:
        missing.append("최소 8자")
    min_days = int_or_none(login_defs.get("MIN_DAYS"))
    max_days = int_or_none(login_defs.get("MAX_DAYS"))
    if min_days is None or min_days < 1:
        missing.append("최소 사용 기간 1일")
    if max_days is None or not 1 <= max_days <= 90:
        missing.append("최대 사용 기간 90일")
    if settings.get("remember", 0) < 4:
        missing.append("최근 비밀번호 4회 기억")
    if missing:
        return vulnerable(f"비밀번호 관리정책 미흡: {', '.join(missing)}")
    return good("비밀번호 복잡성·길이·사용 기간·재사용 제한이 모두 설정되어 있습니다")


def u03(section: Section, _: ParsedLog) -> Judgement:
    denies = [int(value) for value in re.findall(r"\bdeny\s*=\s*(\d+)", section.text())]
    if not denies:
        return vulnerable("계정 잠금 임계값(deny)이 설정되어 있지 않습니다")
    deny = denies[0]
    if 1 <= deny <= 10:
        return good(f"계정 잠금 임계값이 {deny}회로 설정되어 있습니다")
    return vulnerable(f"계정 잠금 임계값이 {deny}회로 기준(10회 이하)을 벗어납니다")


def u04(section: Section, _: ParsedLog) -> Judgement:
    count = int_or_none(next(iter(section.values("NON_SHADOW_COUNT")), None))
    shadow_listed = any(
        "/etc/shadow" in line and not line.startswith("$") and "No such file" not in line
        for line in section.lines
    )
    if count is None:
        return vulnerable("패스워드 파일 점검 결과를 읽지 못했습니다(수동 확인 필요)")
    if count == 0 and shadow_listed:
        return good("모든 계정이 쉐도우 패스워드를 사용합니다")
    return vulnerable(
        f"쉐도우 패스워드를 쓰지 않는 계정이 {count}개 있거나 /etc/shadow 가 없습니다"
    )


def u14(section: Section, _: ParsedLog) -> Judgement:
    paths = section.values("PATH")
    if not paths:
        return vulnerable("root 계정 PATH 를 확인하지 못했습니다(수동 확인 필요)")
    entries = paths[-1].split(":")
    risky = [index for index, entry in enumerate(entries[:-1]) if entry in ("", ".")]
    if risky:
        return vulnerable("PATH 의 맨 앞이나 중간에 현재 디렉터리('.' 또는 빈 항목)가 있습니다")
    return good("PATH 의 맨 앞이나 중간에 현재 디렉터리가 없습니다")


def u15(section: Section, _: ParsedLog) -> Judgement:
    found = [line for line in section.command_output("-nouser") or [] if line.strip()]
    if found:
        return vulnerable(f"소유자나 그룹이 없는 파일·디렉터리가 {len(found)}개 있습니다")
    return good("소유자나 그룹이 없는 파일·디렉터리가 없습니다")


def _file_mode(section: Section, limit: int, label: str) -> Judgement:
    match = _MODE.search(section.text())
    if not match:
        return vulnerable(f"{label} 의 소유자·권한을 확인하지 못했습니다(수동 확인 필요)")
    owner, mode = match.group(1), int(match.group(2), 8)
    if owner == "root" and mode & ~limit & 0o7777 == 0:
        return good(f"{label} 소유자 root, 권한 {match.group(2)} 입니다")
    return vulnerable(
        f"{label} 소유자 {owner}, 권한 {match.group(2)} 로 기준(root, {limit:o} 이하)을 벗어납니다"
    )


def u16(section: Section, _: ParsedLog) -> Judgement:
    return _file_mode(section, 0o644, "/etc/passwd")


def u18(section: Section, _: ParsedLog) -> Judgement:
    return _file_mode(section, 0o400, "/etc/shadow")


def u34(section: Section, _: ParsedLog) -> Judgement:
    if _enabled_units(section.command_output("finger")) or _listening(
        section.command_output(":79")
    ):
        return vulnerable("Finger 서비스가 활성화되어 있습니다")
    return good("Finger 서비스가 비활성화되어 있습니다")


def u35(section: Section, _: ParsedLog) -> Judgement:
    """공유 서비스(FTP·Samba) 익명 접근 제한."""
    text = section.text()
    if re.search(r"^anonymous_enable\s*=\s*YES", text, re.IGNORECASE | re.MULTILINE):
        return vulnerable("vsftpd 에서 익명 FTP(anonymous_enable=YES)가 허용되어 있습니다")
    if any(line.strip() for line in section.command_output("<Anonymous") or []):
        return vulnerable("ProFTPD 에 익명 FTP(<Anonymous>) 설정이 있습니다")
    samba = section.command_output("guest ok") or []
    if any(
        re.search(r"(guest ok|public)\s*=\s*yes|map to guest\s*=\s*bad", line, re.I)
        for line in samba
    ):
        return vulnerable("Samba 공유에서 익명(guest) 접근이 허용되어 있습니다")

    ftp_active = _active(section.command_output("vsftpd proftpd"))
    samba_active = _active(section.command_output("smb smbd"))
    if ftp_active and section.values("ACCOUNT"):
        return vulnerable("FTP 서비스가 실행 중이며 ftp/anonymous 계정이 있습니다")
    ftp_configs_missing = all(
        f"NOT_FOUND={path}" in section.lines
        for path in ("/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf")
    )
    if not ftp_active and not samba_active and ftp_configs_missing and not samba:
        return na("FTP·Samba 공유 서비스를 사용하지 않습니다")
    return good("공유 서비스의 익명 접근이 제한되어 있습니다")


def u36(section: Section, _: ParsedLog) -> Judgement:
    if _enabled_units(section.command_output("rsh|rlogin|rexec")) or _listening(
        section.command_output(":(512|513|514)")
    ):
        return vulnerable("r 계열 서비스(rsh·rlogin·rexec)가 활성화되어 있습니다")
    return good("r 계열 서비스가 비활성화되어 있습니다")


def u64(section: Section, _: ParsedLog) -> Judgement:
    pending = int_or_none(next(iter(section.values("PENDING_SECURITY_UPDATES")), None))
    if pending is None:
        return vulnerable(
            "보안 패치 적용 현황을 자동으로 확인할 수 없습니다(패치 관리 절차 수동 확인 필요)"
        )
    if pending > 0:
        return vulnerable(f"적용되지 않은 보안 업데이트가 {pending}건 있습니다")
    return good("적용 대기 중인 보안 업데이트가 없습니다")


def u66(section: Section, _: ParsedLog) -> Judgement:
    active = _active(section.command_output("rsyslog syslog-ng"))
    text = section.text()
    has_auth = re.search(r"^\s*(auth,)?authpriv\.\*|^\s*auth\.\*", text, re.MULTILINE) is not None
    has_general = re.search(r"^\s*\*\.(info|\*)", text, re.MULTILINE) is not None
    if not active:
        return vulnerable("시스템 로깅 서비스(rsyslog·syslog-ng)가 실행 중이 아닙니다")
    if has_auth and has_general:
        return good("로깅 서비스가 실행 중이며 인증·일반 로그 정책이 설정되어 있습니다")
    return vulnerable(
        "로깅 서비스는 실행 중이나 인증(authpriv) 또는 일반(*.info) 로그 정책이 없습니다"
    )


LINUX_RULES: list[Rule] = [
    Rule("U-01", "U-01", u01),
    Rule("U-02", "U-02", u02),
    Rule("U-03", "U-03", u03),
    Rule("U-04", "U-04", u04),
    Rule("U-14", "U-14", u14),
    Rule("U-15", "U-15", u15),
    Rule("U-16", "U-16", u16),
    Rule("U-18", "U-18", u18),
    Rule("U-34", "U-34", u34),
    Rule("U-35", "U-35", u35),
    Rule("U-36", "U-36", u36),
    Rule("U-64", "U-64", u64),
    Rule("U-66", "U-66", u66),
]

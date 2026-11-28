"""KISA 2026 Unix 계정·파일 관리 '상' 항목 판정 규칙 (kisa_check_linux.sh v1.2 이상).

근거가 부족해 자동으로 확정할 수 없으면 보수적으로 '취약'으로 판정하고 사유를 남긴다.
"""

import re

from modules.compliance.judgement import (
    FileStat,
    Judgement,
    Rule,
    active_services,
    exceeds,
    file_stats,
    good,
    inet_enabled,
    int_or_none,
    na,
    vulnerable,
)
from modules.parser.log_parser import ParsedLog, Section

V12 = (1, 2, 0)
ROOT_OWNERS = frozenset({"root"})
SYSTEM_OWNERS = frozenset({"root", "bin", "sys"})


def _names(stats: list[FileStat], limit: int = 5) -> str:
    shown = ", ".join(f"{s.path}({s.owner}, {s.mode_text})" for s in stats[:limit])
    return shown + (f" 외 {len(stats) - limit}개" if len(stats) > limit else "")


def _file_rule(
    section: Section, label: str, owners: frozenset[str], limit: int, *, missing: Judgement
) -> Judgement:
    stats = file_stats(section.lines)
    if not stats:
        if section.values("MISSING"):
            return missing
        return vulnerable(f"{label} 의 소유자·권한을 확인하지 못했습니다(수동 확인 필요)")
    bad = [s for s in stats if s.owner not in owners or exceeds(s.mode, limit)]
    owner_text = "·".join(sorted(owners))
    if bad:
        return vulnerable(f"기준(소유자 {owner_text}, 권한 {limit:o} 이하)을 벗어남: {_names(bad)}")
    return good(f"{_names(stats)} — 소유자·권한이 기준({owner_text}, {limit:o} 이하)을 만족합니다")


def u05(section: Section, _: ParsedLog) -> Judgement:
    accounts = section.values("UID0")
    others = [name for name in accounts if name != "root"]
    if not accounts:
        return vulnerable("UID 0 계정 목록을 확인하지 못했습니다(수동 확인 필요)")
    if others:
        return vulnerable(f"root 외에 UID 0 인 계정이 있습니다: {', '.join(others)}")
    return good("UID 0 계정은 root 하나뿐입니다")


def u06(section: Section, _: ParsedLog) -> Judgement:
    pam = section.command_output("/etc/pam.d/su") or []
    if any(re.match(r"^\s*auth\s+(required|requisite)\s+\S*pam_wheel\.so", line) for line in pam):
        return good("PAM(pam_wheel.so)으로 su 사용을 wheel 그룹에 제한하고 있습니다")
    su = next((s for s in file_stats(section.lines) if s.path.endswith("/su")), None)
    if su and su.group not in ("root", "") and su.mode & 0o007 == 0:
        return good(f"su 실행 파일이 {su.group} 그룹 전용(권한 {su.mode_text})입니다")
    users = int_or_none(next(iter(section.values("NORMAL_USERS")), None))
    if users == 0:
        return good("일반 사용자 계정 없이 root 만 사용하므로 su 제한이 필요하지 않습니다")
    detail = f"su 권한 {su.mode_text}, 그룹 {su.group}" if su else "su 실행 파일 정보 없음"
    return vulnerable(f"모든 사용자가 su 를 사용할 수 있습니다({detail}, pam_wheel 미설정)")


def u17(section: Section, _: ParsedLog) -> Judgement:
    bad = file_stats(section.lines, prefix="BAD ")
    total = int_or_none(next(iter(section.values("STARTUP_FILES")), None))
    if bad:
        return vulnerable(
            f"소유자가 root 가 아니거나 일반 사용자 쓰기 권한이 있는 시작 스크립트: {_names(bad)}"
        )
    if not total:
        return vulnerable("시스템 시작 스크립트를 찾지 못했습니다(수동 확인 필요)")
    return good(f"시작 스크립트 {total}개 모두 root 소유이며 일반 사용자 쓰기 권한이 없습니다")


def u19(section: Section, _: ParsedLog) -> Judgement:
    return _file_rule(
        section, "/etc/hosts", ROOT_OWNERS, 0o644, missing=vulnerable("/etc/hosts 가 없습니다")
    )


def u20(section: Section, _: ParsedLog) -> Judgement:
    return _file_rule(
        section,
        "/etc/(x)inetd.conf",
        ROOT_OWNERS,
        0o600,
        missing=na("inetd·xinetd 설정 파일이 없습니다(서비스 미사용)"),
    )


def u21(section: Section, _: ParsedLog) -> Judgement:
    return _file_rule(
        section,
        "/etc/(r)syslog.conf",
        SYSTEM_OWNERS,
        0o640,
        missing=vulnerable("syslog 설정 파일을 찾지 못했습니다(수동 확인 필요)"),
    )


def u22(section: Section, _: ParsedLog) -> Judgement:
    return _file_rule(
        section,
        "/etc/services",
        SYSTEM_OWNERS,
        0o644,
        missing=vulnerable("/etc/services 가 없습니다(수동 확인 필요)"),
    )


# 일반 운영에 필요 없는데 SUID·SGID 가 설정되면 권한 상승에 악용되는 대표 실행 파일
# (KISA 기존 점검 목록)
UNNEEDED_SPECIAL = frozenset(
    name
    for base in ("/sbin", "/usr/sbin", "/bin", "/usr/bin")
    for name in (
        f"{base}/dump",
        f"{base}/restore",
        f"{base}/lpq",
        f"{base}/lpq-lpd",
        f"{base}/lpr",
        f"{base}/lpr-lpd",
        f"{base}/lprm",
        f"{base}/lprm-lpd",
        f"{base}/lpc",
        f"{base}/lpc-lpd",
        f"{base}/traceroute",
        f"{base}/newgrp",
        f"{base}/at",
    )
)
# 경로 비교용 문자열이며 임시 파일을 만들지 않는다
USER_WRITABLE_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")  # noqa: S108


def u23(section: Section, _: ParsedLog) -> Judgement:
    files = section.values("SPECIAL")
    if section.command_output("-perm -4000") is None:
        return vulnerable("SUID·SGID 파일 목록을 확인하지 못했습니다(수동 확인 필요)")
    risky = [f for f in files if f in UNNEEDED_SPECIAL or f.startswith(USER_WRITABLE_DIRS)]
    if risky:
        return vulnerable(
            f"불필요하거나 의심스러운 SUID·SGID 파일 {len(risky)}개: {', '.join(risky[:8])}"
        )
    return good(
        f"SUID·SGID 파일 {len(files)}개 중 불필요하거나 의심스러운 파일이 없습니다(목록 검토 권장)"
    )


def u24(section: Section, _: ParsedLog) -> Judgement:
    stats = file_stats(section.lines)
    if section.command_output("<home>") is None:
        return vulnerable("환경변수 파일 정보를 확인하지 못했습니다(수동 확인 필요)")
    bad = [s for s in stats if s.owner not in ("root", s.fields.get("USER", "")) or s.mode & 0o022]
    if bad:
        return vulnerable(
            f"소유자가 다르거나 다른 사용자 쓰기 권한이 있는 환경변수 파일: {_names(bad)}"
        )
    return good(f"환경변수 파일 {len(stats)}개 모두 소유자만 쓸 수 있습니다")


def u25(section: Section, _: ParsedLog) -> Judgement:
    files = section.values("WORLD_WRITABLE")
    if section.command_output("-perm -0002") is None:
        return vulnerable("world writable 파일 목록을 확인하지 못했습니다(수동 확인 필요)")
    if files:
        more = " 이상" if len(files) >= 50 else ""
        return vulnerable(
            f"world writable 파일 {len(files)}개{more}: {', '.join(files[:5])} "
            "— 설정 이유를 확인하고, 필요한 파일이면 사유와 함께 판정을 변경하세요"
        )
    return good("world writable 파일이 없습니다")


def u26(section: Section, _: ParsedLog) -> Judgement:
    files = section.values("DEV_FILE")
    if section.command_output("find /dev") is None:
        return vulnerable("/dev 점검 결과를 확인하지 못했습니다(수동 확인 필요)")
    if files:
        return vulnerable(f"/dev 에 장치가 아닌 일반 파일이 있습니다: {', '.join(files[:5])}")
    return good("/dev 에 존재하지 않는 장치 파일(일반 파일)이 없습니다")


def u27(section: Section, _: ParsedLog) -> Judgement:
    r_services = active_services(section) + inet_enabled(section)
    stats = file_stats(section.lines)
    problems: list[str] = []
    for stat in stats:
        reasons = []
        if stat.owner not in ("root", stat.fields.get("USER", "")):
            reasons.append(f"소유자 {stat.owner}")
        if exceeds(stat.mode, 0o600):
            reasons.append(f"권한 {stat.mode_text}")
        if (int_or_none(stat.fields.get("PLUS")) or 0) > 0:
            reasons.append("'+' 설정")
        if reasons:
            problems.append(f"{stat.path}({', '.join(reasons)})")
    if not r_services:
        if problems:
            return good(
                "r 계열 서비스를 사용하지 않습니다(참고: "
                + "; ".join(problems[:3])
                + " — 파일 삭제 권장)"
            )
        return good("r 계열 서비스를 사용하지 않으며 hosts.equiv·.rhosts 설정 문제가 없습니다")
    if problems:
        return vulnerable(
            "r 계열 서비스 사용 중, 신뢰 호스트 파일 설정 미흡: " + "; ".join(problems)
        )
    return good("r 계열 서비스 사용 중이나 hosts.equiv·.rhosts 소유자·권한·'+' 설정이 적절합니다")


def u28(section: Section, _: ParsedLog) -> Judgement:
    deny = section.command_output("/etc/hosts.deny") or []
    if any(re.match(r"^\s*ALL\s*:\s*ALL\b", line, re.IGNORECASE) for line in deny):
        return good("TCP Wrapper(hosts.deny ALL:ALL)로 허용 호스트만 접속하도록 제한합니다")
    ufw = section.command_output("ufw status") or []
    if any(line.strip().lower() == "status: active" for line in ufw):
        return good("UFW 방화벽이 활성화되어 접속 IP·포트를 제한합니다")
    if "firewalld" in active_services(section):
        return good("firewalld 방화벽이 활성화되어 접속 IP·포트를 제한합니다")
    rules = int_or_none(next(iter(section.values("IPTABLES_INPUT_RULES")), None)) or 0
    policy = next(iter(section.values("IPTABLES_INPUT_POLICY")), "")
    if rules > 0 or policy in ("DROP", "REJECT"):
        return good(
            f"iptables INPUT 규칙 {rules}개(기본 정책 {policy or '확인 불가'})로 접속을 제한합니다"
        )
    if (int_or_none(next(iter(section.values("NFT_INPUT_RULES")), None)) or 0) > 0:
        return good("nftables 입력 규칙으로 접속을 제한합니다")
    return vulnerable("TCP Wrapper·방화벽(UFW·firewalld·iptables·nftables) 접속 제한이 없습니다")


FILE_RULES: list[Rule] = [
    Rule("U-05", "U-05", u05, V12),
    Rule("U-06", "U-06", u06, V12),
    Rule("U-17", "U-17", u17, V12),
    Rule("U-19", "U-19", u19, V12),
    Rule("U-20", "U-20", u20, V12),
    Rule("U-21", "U-21", u21, V12),
    Rule("U-22", "U-22", u22, V12),
    Rule("U-23", "U-23", u23, V12),
    Rule("U-24", "U-24", u24, V12),
    Rule("U-25", "U-25", u25, V12),
    Rule("U-26", "U-26", u26, V12),
    Rule("U-27", "U-27", u27, V12),
    Rule("U-28", "U-28", u28, V12),
]

"""KISA 2026 Unix 중요도 '중'·'하' 항목 판정 규칙 (kisa_check_linux.sh v1.3 이상).

업무상 필요 여부처럼 자동으로 알 수 없는 부분은 객관적 기준으로 판정하고,
예외는 사유와 함께 판정을 변경하도록 사유에 안내한다.
"""

import re

from modules.compliance.judgement import (
    Judgement,
    Rule,
    active_services,
    exceeds,
    file_stats,
    good,
    inet_enabled,
    int_or_none,
    kv,
    listening_ports,
    na,
    vulnerable,
)
from modules.compliance.kisa_linux_services import _mail_agents, _snmp_entries
from modules.parser.log_parser import ParsedLog, Section

V13 = (1, 3, 0)
NO_LOGIN = re.compile(r"(nologin|false)$")


def _entries(section: Section, key: str) -> list[dict[str, str]]:
    return [kv(line) for line in section.lines if line.startswith(f"{key}=")]


def _running(section: Section) -> list[str]:
    return active_services(section) + inet_enabled(section)


def _listing(values: list[str], limit: int = 6) -> str:
    shown = ", ".join(values[:limit])
    return shown + (f" 외 {len(values) - limit}개" if len(values) > limit else "")


# --- 계정 관리 ----------------------------------------------------------------------------------


def u07(section: Section, _: ParsedLog) -> Judgement:
    if section.values("LASTLOG") == ["unavailable"]:
        return vulnerable("마지막 로그인 기록(lastlog)을 확인할 수 없습니다(수동 확인 필요)")
    stale = [
        a["ACCOUNT"]
        for a in _entries(section, "ACCOUNT")
        if a.get("STALE") == "yes" and (int_or_none(a.get("UID")) or 0) >= 1000
    ]
    defaults = [
        d["DEFAULT_ACCOUNT"]
        for d in _entries(section, "DEFAULT_ACCOUNT")
        if not NO_LOGIN.search(d.get("SHELL", ""))
    ]
    problems = []
    if stale:
        problems.append(f"90일 넘게 로그인하지 않은 계정 {_listing(stale)}")
    if defaults:
        problems.append(f"로그인 가능한 기본 불필요 계정 {_listing(defaults)}")
    if problems:
        return vulnerable("; ".join(problems) + " — 필요한 계정이면 사유와 함께 판정을 변경하세요")
    return good("장기 미사용 일반 계정과 로그인 가능한 기본 불필요 계정(lp·uucp·nuucp)이 없습니다")


def u08(section: Section, _: ParsedLog) -> Judgement:
    members = sorted({u["USER"] for u in _entries(section, "USER") if u["USER"] != "root"})
    if members:
        return vulnerable(
            f"관리자 그룹(root, GID 0)에 root 외 계정이 있습니다: {_listing(members)}"
        )
    return good("관리자 그룹(root, GID 0)에 root 외 계정이 없습니다")


def u09(section: Section, _: ParsedLog) -> Judgement:
    groups = [g["GROUP"] for g in _entries(section, "GROUP") if g.get("EMPTY") == "yes"]
    if groups:
        return vulnerable(
            f"구성원이 없는 그룹(GID 1000 이상): {_listing(groups)} — 관리자 검토 후 제거하세요"
        )
    return good("계정이 속하지 않은 불필요한 그룹이 없습니다")


def u10(section: Section, _: ParsedLog) -> Judgement:
    duplicates = [
        f"UID {d['DUP_UID']}({d.get('COUNT', '?')}개)" for d in _entries(section, "DUP_UID")
    ]
    if duplicates:
        return vulnerable(f"같은 UID 를 쓰는 계정이 있습니다: {', '.join(duplicates)}")
    return good("동일한 UID 를 가진 계정이 없습니다")


def u11(section: Section, _: ParsedLog) -> Judgement:
    accounts = section.values("SYSTEM_SHELL")
    if accounts:
        return vulnerable(f"로그인이 필요 없는 시스템 계정에 쉘이 있습니다: {_listing(accounts)}")
    return good("로그인이 필요 없는 시스템 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있습니다")


def u12(section: Section, _: ParsedLog) -> Judgement:
    timeouts = [
        int(m.group(1))
        for line in section.command_output("TMOUT=") or []
        if (m := re.search(r"TMOUT=(\d+)", line))
    ]
    autologout = [
        int(m.group(1))
        for line in section.command_output("autologout") or []
        if (m := re.search(r"autologout\s*=\s*(\d+)", line))
    ]
    if any(0 < t <= 600 for t in timeouts) or any(0 < m <= 10 for m in autologout):
        value = min([t for t in timeouts if t > 0] or [m * 60 for m in autologout])
        return good(f"세션 종료 시간(TMOUT)이 {value}초로 설정되어 있습니다")
    if timeouts or autologout:
        return vulnerable(f"세션 종료 시간이 600초를 넘습니다(TMOUT {timeouts or autologout})")
    return vulnerable("세션 종료 시간(TMOUT)이 설정되어 있지 않습니다")


STRONG_HASHES = {
    "5": "SHA-256",
    "6": "SHA-512",
    "y": "yescrypt",
    "gy": "gost-yescrypt",
    "2a": "bcrypt",
    "2b": "bcrypt",
    "2y": "bcrypt",
    "7": "scrypt",
}
WEAK_HASHES = {"1": "MD5", "des": "DES", "md5": "MD5", "2": "bcrypt(구형)", "3": "NT-Hash"}
STRONG_METHODS = {"SHA256", "SHA512", "YESCRYPT", "BCRYPT", "GOST_YESCRYPT", "SCRYPT"}


def u13(section: Section, _: ParsedLog) -> Judgement:
    algos = {
        a["HASH_ALGO"]: int_or_none(a.get("COUNT")) or 0 for a in _entries(section, "HASH_ALGO")
    }
    method_line = next(iter(section.command_output("ENCRYPT_METHOD") or []), "")
    method = method_line.split()[-1].upper() if method_line.strip() else ""
    weak = [f"{WEAK_HASHES.get(k, k)} {v}개" for k, v in algos.items() if k not in STRONG_HASHES]
    if weak:
        return vulnerable(f"취약한 알고리즘으로 저장된 비밀번호가 있습니다: {', '.join(weak)}")
    if method and method not in STRONG_METHODS:
        return vulnerable(f"비밀번호 암호화 기본 알고리즘이 {method} 입니다(SHA-2 이상 필요)")
    if not algos and not method:
        return vulnerable("비밀번호 암호화 알고리즘을 확인하지 못했습니다(수동 확인 필요)")
    used = ", ".join(sorted({STRONG_HASHES[k] for k in algos})) or "저장된 비밀번호 없음"
    return good(f"SHA-2 이상 알고리즘을 사용합니다(기본 {method or '미지정'}, 사용 중 {used})")


# --- 파일·디렉터리 관리 --------------------------------------------------------------------------


def u29(section: Section, _: ParsedLog) -> Judgement:
    stats = file_stats(section.lines)
    if not stats:
        return good("/etc/hosts.lpd 파일이 없습니다")
    s = stats[0]
    if s.owner != "root" or exceeds(s.mode, 0o600):
        return vulnerable(
            f"/etc/hosts.lpd 소유자 {s.owner}, 권한 {s.mode_text}(root·600 이하 필요)"
        )
    return good(f"/etc/hosts.lpd 소유자 root, 권한 {s.mode_text} 입니다")


def u30(section: Section, _: ParsedLog) -> Judgement:
    shell = [
        line.strip() for line in section.command_output("bash -lc umask") or [] if line.strip()
    ]
    value = shell[0] if shell and re.fullmatch(r"[0-7]{3,4}", shell[0]) else None
    if value is None:
        configured = re.findall(r"umask\s+([0-7]{3,4})", section.text(), re.IGNORECASE)
        value = configured[0] if configured else None
    if value is None:
        return vulnerable("UMASK 값을 확인하지 못했습니다(수동 확인 필요)")
    if int(value, 8) & 0o022 == 0o022:
        return good(f"UMASK 가 {value} 로 그룹·기타 사용자 쓰기 권한을 막습니다")
    return vulnerable(f"UMASK 가 {value} 로 022 미만입니다")


def u31(section: Section, _: ParsedLog) -> Judgement:
    stats = file_stats(section.lines)
    bad = [
        f"{s.path}(소유자 {s.owner}, 권한 {s.mode_text})"
        for s in stats
        if s.owner != s.fields.get("USER") or s.mode & 0o002
    ]
    if bad:
        return vulnerable(
            f"소유자가 다르거나 다른 사용자 쓰기 권한이 있는 홈 디렉터리: {_listing(bad)}"
        )
    return good(
        f"일반 사용자 홈 디렉터리 {len(stats)}개 모두 본인 소유이며 타 사용자 쓰기 권한이 없습니다"
    )


def u32(section: Section, _: ParsedLog) -> Judgement:
    missing = [u["USER"] for u in _entries(section, "USER") if u.get("HOME_EXISTS") == "no"]
    if missing:
        return vulnerable(f"홈 디렉터리가 없는 계정: {_listing(missing)}")
    return good("홈 디렉터리가 존재하지 않는 계정이 없습니다")


def u33(section: Section, _: ParsedLog) -> Judgement:
    hidden = section.values("HIDDEN")
    if hidden:
        return vulnerable(
            f"임시·장치 디렉터리에 숨겨진 파일이 있습니다: {_listing(hidden, 4)} "
            "— 정상 파일이면 사유와 함께 판정을 변경하세요"
        )
    return good("임시·장치 디렉터리에 의심스러운 숨겨진 파일이 없습니다")


# --- 서비스 관리 --------------------------------------------------------------------------------


def u48(section: Section, _: ParsedLog) -> Judgement:
    agents = _mail_agents(section)
    if not agents:
        return na("메일 서비스를 사용하지 않습니다")
    problems = []
    if "sendmail" in agents:
        options = " ".join(section.command_output("PrivacyOptions") or [])
        if "goaway" not in options and not ("noexpn" in options and "novrfy" in options):
            problems.append("sendmail PrivacyOptions 에 noexpn·novrfy(또는 goaway) 없음")
    if "postfix" in agents:
        vrfy = " ".join(section.command_output("disable_vrfy_command") or [])
        if not re.search(r"disable_vrfy_command\s*=\s*yes", vrfy):
            problems.append("postfix disable_vrfy_command 가 yes 가 아님")
    if "exim" in agents:
        acl = " ".join(section.command_output("acl_smtp_") or [])
        if re.search(r"acl_smtp_(vrfy|expn)\s*=\s*accept", acl):
            problems.append("exim 이 VRFY·EXPN 을 허용함")
    if problems:
        return vulnerable("expn·vrfy 명령어가 제한되지 않았습니다: " + ", ".join(problems))
    return good("메일 서비스의 expn·vrfy 명령어 사용이 제한되어 있습니다")


def u51(section: Section, _: ParsedLog) -> Judgement:
    if not _running(section):
        return na("DNS 서비스를 사용하지 않습니다")
    lines = section.command_output("allow-update") or []
    if any(re.search(r"allow-update\s*\{\s*any\s*;", line) for line in lines):
        return vulnerable("allow-update { any; } 로 모든 호스트의 동적 업데이트를 허용합니다")
    return good("DNS 동적 업데이트가 비활성화되어 있거나 허가된 호스트·키로 제한되어 있습니다")


def u52(section: Section, _: ParsedLog) -> Judgement:
    found = _running(section) + section.values("PROCESS")
    if 23 in listening_ports(section):
        found.append("포트 23")
    if found:
        return vulnerable(f"Telnet 서비스가 활성화되어 있습니다: {', '.join(dict.fromkeys(found))}")
    return good("Telnet 서비스가 비활성화되어 있습니다")


FTP_DAEMONS = ("vsftpd", "proftpd", "pure-ftpd")


def _ftp(section: Section) -> list[str]:
    return [s for s in active_services(section) if s in FTP_DAEMONS] + inet_enabled(section)


def u53(section: Section, _: ParsedLog) -> Judgement:
    daemons = _ftp(section)
    if not daemons:
        return na("FTP 서비스를 사용하지 않습니다")
    banner = [line for line in section.command_output("ftpd_banner") or [] if line.strip()]
    if "vsftpd" in daemons and not banner:
        return vulnerable("vsftpd 기본 배너가 서비스 이름·버전을 노출합니다(ftpd_banner 미설정)")
    if "proftpd" in daemons:
        ident = " ".join(section.command_output("ServerIdent") or [])
        if not re.search(r"ServerIdent\s+(off|on\s+\")", ident, re.IGNORECASE):
            return vulnerable("ProFTPD 배너가 서비스 정보를 노출합니다(ServerIdent 미설정)")
    if "pure-ftpd" in daemons:
        return vulnerable("pure-ftpd 배너 설정을 자동으로 확인할 수 없습니다(수동 확인 필요)")
    return good("FTP 접속 배너에 서비스 정보가 노출되지 않도록 설정되어 있습니다")


def u54(section: Section, _: ParsedLog) -> Judgement:
    daemons = _ftp(section)
    if not daemons:
        return good("FTP 서비스를 사용하지 않습니다")
    text = section.text()
    vsftpd_tls = re.search(
        r"^\s*ssl_enable\s*=\s*YES", text, re.MULTILINE | re.IGNORECASE
    ) and not re.search(
        r"^\s*force_local_(logins|data)_ssl\s*=\s*NO", text, re.MULTILINE | re.IGNORECASE
    )
    proftpd_tls = re.search(r"^\s*TLSRequired\s+on", text, re.MULTILINE | re.IGNORECASE)
    plain = [
        d
        for d in daemons
        if not ((d == "vsftpd" and vsftpd_tls) or (d == "proftpd" and proftpd_tls))
    ]
    if plain:
        return vulnerable(f"암호화되지 않은 FTP 서비스가 활성화되어 있습니다: {', '.join(plain)}")
    return good("FTP 서비스가 TLS(FTPS) 암호화를 요구합니다")


def u55(section: Section, _: ParsedLog) -> Judgement:
    shells = section.values("FTP_ACCOUNT_SHELL")
    if not shells:
        return good("ftp 계정이 없습니다")
    if NO_LOGIN.search(shells[0]):
        return good(f"ftp 계정에 로그인 불가 쉘({shells[0]})이 부여되어 있습니다")
    return vulnerable(f"ftp 계정에 로그인 가능한 쉘({shells[0] or '없음'})이 부여되어 있습니다")


def u56(section: Section, _: ParsedLog) -> Judgement:
    if not _ftp(section):
        return na("FTP 서비스를 사용하지 않습니다")
    text = section.text()
    wrappers = re.search(r"^\s*tcp_wrappers\s*=\s*YES", text, re.MULTILINE | re.IGNORECASE)
    allow_rules = [
        line for line in section.command_output("/etc/hosts.allow") or [] if line.strip()
    ]
    proftpd_rules = section.command_output("Allow|Deny") or []
    if (
        any(re.match(r"^\s*ALL\s*:\s*ALL", line, re.IGNORECASE) for line in allow_rules)
        or (wrappers and allow_rules)
        or proftpd_rules
    ):
        return good(
            "FTP 서비스에 접속 허용 호스트 제한(TCP Wrapper·Allow from)이 설정되어 있습니다"
        )
    return vulnerable("FTP 서비스에 IP 주소 접근 제어 설정이 없습니다")


def u57(section: Section, _: ParsedLog) -> Judgement:
    daemons = _ftp(section)
    if not daemons:
        return na("FTP 서비스를 사용하지 않습니다")
    if any(line.strip() == "root" for line in section.command_output("^[[:space:]]*root") or []):
        return good("ftpusers 파일에 root 가 등록되어 FTP root 접속이 차단됩니다")
    if daemons == ["proftpd"] and not re.search(r"RootLogin\s+on", section.text(), re.IGNORECASE):
        return good("ProFTPD 기본값(RootLogin off)으로 root 접속이 차단됩니다")
    return vulnerable("FTP 서비스에서 root 계정 접속을 차단하지 않습니다(ftpusers 에 root 없음)")


def u58(section: Section, _: ParsedLog) -> Judgement:
    if _running(section):
        return vulnerable(
            "SNMP 서비스를 사용 중입니다. 업무상 필요하면 사유와 함께 판정을 변경하세요"
        )
    return good("SNMP 서비스를 사용하지 않습니다")


def u60(section: Section, _: ParsedLog) -> Judgement:
    if not _running(section):
        return na("SNMP 서비스를 사용하지 않습니다")
    entries = _snmp_entries(section)
    legacy = [e for e in entries if "COMMUNITY" in e]
    if not legacy:
        if entries:
            return good("SNMP v3 사용자 인증만 사용합니다(v3 비밀번호 복잡도는 별도 확인)")
        return vulnerable("SNMP 커뮤니티 설정을 확인하지 못했습니다(수동 확인 필요)")
    defaults = [e for e in legacy if e.get("COMMUNITY") in ("public", "private")]
    weak = [e for e in legacy if e.get("STRENGTH") != "ok"]
    if defaults:
        return vulnerable("기본 커뮤니티 이름(public·private)을 사용합니다")
    if weak:
        return vulnerable(
            "복잡도 기준(영문·숫자 10자 이상 또는 특수문자 포함 8자 이상) 미달 커뮤니티 "
            f"{len(weak)}개"
        )
    return good(f"SNMP 커뮤니티 {len(legacy)}개가 복잡도 기준을 만족합니다")


WARNING_WORDS = re.compile(
    r"경고|무단|허가|불법|인가|감시|처벌|unauthori[sz]ed|authori[sz]ed|warning|prohibit|monitor|prosecut",
    re.IGNORECASE,
)


def u62(section: Section, _: ParsedLog) -> Judgement:
    banners = [
        line.removeprefix("BANNER_TEXT: ")
        for line in section.lines
        if line.startswith("BANNER_TEXT: ")
    ]
    has_warning = any(WARNING_WORDS.search(line) for line in banners)
    ssh = " ".join(section.command_output("^banner") or []).strip().lower()
    if not has_warning:
        return vulnerable("로그인 시 경고 메시지(motd·issue)가 설정되어 있지 않습니다")
    if ssh.endswith("none"):
        return vulnerable(
            "서버 경고 메시지는 있으나 SSH 로그인 배너(Banner)가 설정되어 있지 않습니다"
        )
    return good("로그인 시 불법 사용 경고 메시지가 설정되어 있습니다")


def u63(section: Section, _: ParsedLog) -> Judgement:
    stats = file_stats(section.lines)
    if not stats:
        return na("/etc/sudoers 가 없습니다(sudo 미사용)")
    s = stats[0]
    if s.owner != "root" or exceeds(s.mode, 0o640):
        return vulnerable(f"/etc/sudoers 소유자 {s.owner}, 권한 {s.mode_text}(root·640 이하 필요)")
    return good(f"/etc/sudoers 소유자 root, 권한 {s.mode_text} 입니다")


# --- 로그 관리 ----------------------------------------------------------------------------------


def u65(section: Section, _: ParsedLog) -> Judgement:
    services = active_services(section)
    synced = "NTPSynchronized=yes" in section.lines
    sources = section.values("TIME_SOURCE") + [
        line for line in section.command_output("NTP|FallbackNTP") or [] if line.strip()
    ]
    if synced:
        return good("시스템 시각이 NTP 서버와 동기화되어 있습니다")
    if services and (sources or "systemd-timesyncd" in services):
        return good(
            f"시각 동기화 서비스({', '.join(services)})가 동작하며 기준 서버가 설정되어 있습니다"
        )
    if services:
        return vulnerable(
            f"시각 동기화 서비스({', '.join(services)})에 기준 서버가 설정되어 있지 않습니다"
        )
    return vulnerable("NTP 시각 동기화 서비스가 동작하지 않습니다")


def u67(section: Section, _: ParsedLog) -> Judgement:
    bad = file_stats(section.lines, prefix="BAD ")
    total = int_or_none(next(iter(section.values("LOG_FILES")), None))
    if bad:
        listed = [f"{s.path}({s.owner}, {s.mode_text})" for s in bad]
        return vulnerable(
            f"소유자가 root 가 아니거나 권한이 644 를 넘는 로그 파일: {_listing(listed, 4)}"
        )
    if not total:
        return vulnerable("로그 파일 정보를 확인하지 못했습니다(수동 확인 필요)")
    return good(f"/var/log 로그 파일 {total}개 모두 root 소유이며 권한이 644 이하입니다")


MEDIUM_LOW_RULES: list[Rule] = [
    Rule(code, code, judge, V13)
    for code, judge in (
        ("U-07", u07),
        ("U-08", u08),
        ("U-09", u09),
        ("U-10", u10),
        ("U-11", u11),
        ("U-12", u12),
        ("U-13", u13),
        ("U-29", u29),
        ("U-30", u30),
        ("U-31", u31),
        ("U-32", u32),
        ("U-33", u33),
        ("U-48", u48),
        ("U-51", u51),
        ("U-52", u52),
        ("U-53", u53),
        ("U-54", u54),
        ("U-55", u55),
        ("U-56", u56),
        ("U-57", u57),
        ("U-58", u58),
        ("U-60", u60),
        ("U-62", u62),
        ("U-63", u63),
        ("U-65", u65),
        ("U-67", u67),
    )
]

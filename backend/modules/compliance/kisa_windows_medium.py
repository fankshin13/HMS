"""KISA 2026 Windows 서버 중요도 '중'·'하' 항목 판정 규칙 (kisa_check_windows.bat).

since: 근거를 수집하기 시작한 스크립트 버전(1.0 에서 이미 모으던 보안 정책 값은 1.0).
정책이 정의되지 않은 경우 Windows 기본값이 기준을 만족하면 양호로 보고 사유에 '기본값'을 밝힌다.
"""

import re

from modules.compliance.judgement import (
    Judgement,
    Rule,
    good,
    int_or_none,
    kv,
    na,
    vulnerable,
)
from modules.compliance.kisa_windows_high import _policy, _running
from modules.parser.log_parser import ParsedLog, Section

V10 = (1, 0, 0)
V12 = (1, 2, 0)
ADMINISTRATORS = "*S-1-5-32-544"


def _entries(section: Section, key: str) -> list[dict[str, str]]:
    return [kv(line) for line in section.lines if line.startswith(f"{key}=")]


def _value(section: Section, key: str) -> str | None:
    values = section.values(key)
    return values[0] if values else None


def _listing(values: list[str], limit: int = 6) -> str:
    shown = ", ".join(values[:limit])
    return shown + (f" 외 {len(values) - limit}개" if len(values) > limit else "")


def _flag(log: ParsedLog, key: str) -> int | None:
    return int_or_none(_policy(log, key))


def _rdp_disabled(log: ParsedLog) -> bool:
    section = log.sections.get("WIN-REMOTE_ACCESS")
    return section is not None and _value(section, "fDenyTSConnections") == "1"


# --- 계정 관리 ----------------------------------------------------------------------------------


def w07(_: Section, log: ParsedLog) -> Judgement:
    value = _flag(log, "EveryoneIncludesAnonymous")
    if value is None:
        return vulnerable("'Everyone 사용 권한을 익명 사용자에게 적용' 정책을 확인하지 못했습니다")
    if value == 0:
        return good("'Everyone 사용 권한을 익명 사용자에게 적용' 정책이 사용 안 함입니다")
    return vulnerable("'Everyone 사용 권한을 익명 사용자에게 적용' 정책이 사용으로 되어 있습니다")


def w08(_: Section, log: ParsedLog) -> Judgement:
    duration = _flag(log, "LockoutDuration")
    reset = _flag(log, "ResetLockoutCount")
    if duration is None or reset is None:
        return vulnerable(
            "계정 잠금 기간이 설정되어 있지 않습니다(잠금 임계값 미설정 시 함께 미설정)"
        )
    if duration >= 60 and reset >= 60:
        return good(f"계정 잠금 기간 {duration}분, 잠금 횟수 초기화 {reset}분으로 60분 이상입니다")
    return vulnerable(f"계정 잠금 기간 {duration}분, 잠금 횟수 초기화 {reset}분(60분 이상 필요)")


def w10(_: Section, log: ParsedLog) -> Judgement:
    if _flag(log, "DontDisplayLastUserName") == 1:
        return good("'마지막 사용자 이름 표시 안 함'이 사용으로 설정되어 있습니다")
    return vulnerable("'마지막 사용자 이름 표시 안 함'이 사용 안 함(기본값)입니다")


def w11(_: Section, log: ParsedLog) -> Judgement:
    value = _policy(log, "SeInteractiveLogonRight")
    if value is None:
        return vulnerable("'로컬 로그온 허용' 정책을 확인하지 못했습니다(수동 확인 필요)")
    holders = [v.strip() for v in value.split(",") if v.strip()]
    others = [
        h
        for h in holders
        if h not in (ADMINISTRATORS, "Administrators") and not h.upper().startswith("IUSR")
    ]
    if others:
        return vulnerable(
            "로컬 로그온 허용 정책에 Administrators·IUSR 외 계정·그룹이 있습니다: "
            f"{', '.join(others)}"
        )
    return good("로컬 로그온 허용 정책에 Administrators(·IUSR)만 있습니다")


def w12(_: Section, log: ParsedLog) -> Judgement:
    value = _flag(log, "LSAAnonymousNameLookup")
    if value is None:
        return vulnerable("'익명 SID/이름 변환 허용' 정책을 확인하지 못했습니다")
    if value == 0:
        return good("'익명 SID/이름 변환 허용' 정책이 사용 안 함입니다")
    return vulnerable("'익명 SID/이름 변환 허용' 정책이 사용으로 되어 있습니다")


def w13(_: Section, log: ParsedLog) -> Judgement:
    value = _flag(log, "LimitBlankPasswordUse")
    if value is None:
        return vulnerable("'콘솔 로그온 시 빈 암호 사용 제한' 정책을 확인하지 못했습니다")
    if value == 1:
        return good("'콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한' 정책이 사용입니다")
    return vulnerable("'콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한' 정책이 사용 안 함입니다")


def w14(section: Section, log: ParsedLog) -> Judgement:
    if _rdp_disabled(log):
        return good("원격 데스크톱을 사용하지 않습니다")
    if section.values("RDP_MEMBER_ERROR"):
        return vulnerable("Remote Desktop Users 그룹을 확인하지 못했습니다(수동 확인 필요)")
    members = [m["RDP_MEMBER"] for m in _entries(section, "RDP_MEMBER")]
    if members:
        return good(f"관리자 외 원격 접속 전용 계정·그룹이 지정되어 있습니다({len(members)}개)")
    return vulnerable(
        "원격 데스크톱 사용 중이나 관리자 외 원격 접속 전용 계정(Remote Desktop Users)이 없습니다"
    )


# --- 서비스 관리 --------------------------------------------------------------------------------


def w28(section: Section, log: ParsedLog) -> Judgement:
    if _rdp_disabled(log):
        return good("원격 데스크톱을 사용하지 않습니다")
    level = int_or_none(_value(section, "MinEncryptionLevel"))
    if level is None:
        return vulnerable("원격 데스크톱 암호화 수준을 확인하지 못했습니다(수동 확인 필요)")
    if level >= 2:
        return good(f"원격 데스크톱 암호화 수준이 {level}(중간 이상)입니다")
    return vulnerable(f"원격 데스크톱 암호화 수준이 {level}(낮음)입니다")


def _snmp_on(log: ParsedLog) -> bool:
    return bool(_running(log, "SNMP"))


def w29(section: Section, log: ParsedLog) -> Judgement:
    if not _snmp_on(log):
        return good("SNMP 서비스를 사용하지 않습니다")
    if _entries(section, "SNMP_COMMUNITY"):
        return good("SNMP 서비스를 Community String 을 설정하여 사용합니다")
    return vulnerable("SNMP 서비스가 Community String 설정 없이 구동 중입니다")


def w30(section: Section, log: ParsedLog) -> Judgement:
    if not _snmp_on(log):
        return good("SNMP 서비스를 사용하지 않습니다")
    defaults = [
        c["SNMP_COMMUNITY"]
        for c in _entries(section, "SNMP_COMMUNITY")
        if c["SNMP_COMMUNITY"] in ("public", "private")
    ]
    if defaults:
        return vulnerable(f"기본 Community String({', '.join(defaults)})을 사용합니다")
    return good("기본 Community String(public·private)을 사용하지 않습니다")


def w31(section: Section, log: ParsedLog) -> Judgement:
    if not _snmp_on(log):
        return good("SNMP 서비스를 사용하지 않습니다")
    managers = int_or_none(_value(section, "SNMP_PERMITTED_MANAGERS")) or 0
    if managers > 0:
        return good(f"SNMP 패킷을 받아들일 호스트 {managers}개가 지정되어 있습니다")
    return vulnerable("모든 호스트로부터 SNMP 패킷을 받아들입니다(허용 호스트 미지정)")


def w32(section: Section, log: ParsedLog) -> Judgement:
    if not _running(log, "DNS"):
        return good("DNS 서비스를 사용하지 않습니다")
    if _value(section, "DNS_ZONES") == "unavailable":
        return vulnerable("DNS 동적 업데이트 설정을 확인하지 못했습니다(수동 확인 필요)")
    updates = section.values("DNS_ZONE_UPDATE")
    enabled = [u for u in updates if u != "None"]
    if enabled:
        return vulnerable(
            f"동적 업데이트가 설정된 DNS 영역이 {len(enabled)}개 있습니다"
            f"({', '.join(sorted(set(enabled)))})"
        )
    return good("DNS 영역의 동적 업데이트가 없음(아니오)으로 설정되어 있습니다")


def w33(section: Section, log: ParsedLog) -> Judgement:
    problems = []
    if _running(log, "W3SVC") and _value(section, "IIS_REMOVE_SERVER_HEADER") != "True":
        problems.append("IIS 응답 헤더에 서버 정보 노출(removeServerHeader 미설정)")
    sites = [
        s["FTP_SITE"] for s in _entries(section, "FTP_SITE") if s.get("SUPPRESS_BANNER") != "True"
    ]
    if sites and _running(log, "FTPSVC", "MSFTPSVC"):
        problems.append(f"FTP 기본 배너 노출({', '.join(sites)})")
    if _running(log, "SMTPSVC"):
        problems.append("SMTP 서비스 배너 확인 필요")
    if problems:
        return vulnerable("서비스 배너 정보가 노출됩니다: " + ", ".join(problems))
    return good("HTTP·FTP·SMTP 서비스를 사용하지 않거나 배너 정보가 차단되어 있습니다")


def w34(section: Section, log: ParsedLog) -> Judgement:
    if not _running(log, "TlntSvr"):
        return good("Telnet 서비스가 구동되어 있지 않습니다")
    if _value(section, "TelnetSecurityMechanism") == "2":
        return good("Telnet 서비스가 NTLM 인증만 사용합니다")
    return vulnerable("Telnet 서비스가 구동 중이며 NTLM 외 인증을 허용합니다")


def w35(section: Section, _: ParsedLog) -> Judgement:
    sources = section.values("ODBC_DSN")
    if sources:
        return vulnerable(
            f"시스템 DSN {len(sources)}개({_listing(sources, 4)}) — "
            "사용하지 않는 데이터 소스는 제거하고, "
            "사용 중이면 사유와 함께 판정을 변경하세요"
        )
    return good("불필요한 ODBC 시스템 데이터 소스가 없습니다")


def w36(section: Section, log: ParsedLog) -> Judgement:
    if _rdp_disabled(log):
        return good("원격 데스크톱을 사용하지 않습니다")
    for key in ("PolicyMaxIdleTime", "RdpMaxIdleTime"):
        ms = int_or_none(_value(section, key))
        if ms is not None and ms > 0:
            minutes = ms // 60000
            if ms <= 30 * 60000:
                return good(f"원격 세션 유휴 시간 제한이 {minutes}분입니다")
            return vulnerable(f"원격 세션 유휴 시간 제한이 {minutes}분으로 30분을 넘습니다")
    return vulnerable("원격 세션 유휴 시간 제한(Timeout)이 설정되어 있지 않습니다")


def w37(section: Section, _: ParsedLog) -> Judgement:
    tasks = [t["TASK"] for t in _entries(section, "TASK")]
    if tasks:
        return vulnerable(
            f"Microsoft 외 예약 작업 {len(tasks)}개({_listing(tasks, 4)}) — "
            "의심스러운 명령이 없는지 "
            "검토 후 사유와 함께 판정을 변경하세요"
        )
    return good("Microsoft 기본 작업 외 예약된 작업이 없습니다")


# --- 로그 관리 ----------------------------------------------------------------------------------

AUDIT_REQUIRED = {
    "AuditAccountManage": (2, "계정 관리 실패"),
    "AuditAccountLogon": (3, "계정 로그온 이벤트 성공/실패"),
    "AuditPrivilegeUse": (3, "권한 사용 성공/실패"),
    "AuditDSAccess": (2, "디렉터리 서비스 액세스 실패"),
    "AuditLogonEvents": (3, "로그온 이벤트 성공/실패"),
    "AuditPolicyChange": (3, "정책 변경 성공/실패"),
}


def w40(_: Section, log: ParsedLog) -> Judgement:
    missing = [
        label
        for key, (mask, label) in AUDIT_REQUIRED.items()
        if (_flag(log, key) or 0) & mask != mask
    ]
    if missing:
        return vulnerable("감사 정책 권고 기준 미충족: " + ", ".join(missing))
    return good(
        "감사 정책이 권고 기준(계정 관리·로그온·권한 사용·정책 변경 등)대로 설정되어 있습니다"
    )


def w41(section: Section, log: ParsedLog) -> Judgement:
    if not _running(log, "W32Time"):
        return vulnerable("Windows 시간 서비스(W32Time)가 구동되어 있지 않습니다")
    kind = _value(section, "W32TimeType") or ""
    if kind in ("NT5DS", "AllSync") or (
        kind == "NTP" and _value(section, "NTP_SERVER_SET") == "True"
    ):
        return good(f"시간 동기화가 설정되어 있습니다(방식 {kind})")
    return vulnerable(f"NTP 시간 동기화 서버가 설정되어 있지 않습니다(방식 {kind or '확인 불가'})")


LOG_MIN_BYTES = 10240 * 1024


def w42(section: Section, _: ParsedLog) -> Judgement:
    sizes: dict[str, int] = {}
    current = ""
    for line in section.lines:
        name = re.match(r"^\s*name:\s*(\S+)", line)
        size = re.match(r"^\s*maxSize:\s*(\d+)", line)
        if name:
            current = name.group(1)
        elif size and current:
            sizes[current] = int(size.group(1))
    if not sizes:
        return vulnerable("이벤트 로그 크기를 확인하지 못했습니다(수동 확인 필요)")
    small = [f"{k} {v // 1024}KB" for k, v in sizes.items() if v < LOG_MIN_BYTES]
    if small:
        return vulnerable(f"최대 로그 크기가 10,240KB 미만입니다: {', '.join(small)}")
    return good(
        f"이벤트 로그({', '.join(sizes)}) 최대 크기가 10,240KB 이상입니다"
        "(2008 이후는 덮어쓰기 기간 지정 불가)"
    )


def w43(section: Section, _: ParsedLog) -> Judgement:
    value = _value(section, "LOGDIR_EVERYONE")
    if value == "False":
        return good("이벤트 로그 폴더 접근 권한에 Everyone 이 없습니다")
    if value == "True":
        return vulnerable("이벤트 로그 폴더 접근 권한에 Everyone 이 있습니다")
    return vulnerable("이벤트 로그 폴더 권한을 확인하지 못했습니다(수동 확인 필요)")


# --- 보안 관리 ----------------------------------------------------------------------------------

# (레지스트리 값 이름, 기준 값, 최솟값 비교 여부, 안내 문구)
DOS_KEYS: list[tuple[str, int, bool, str]] = [
    ("SynAttackProtect", 1, True, "SynAttackProtect 1 이상"),
    ("EnableDeadGWDetect", 0, False, "EnableDeadGWDetect 0"),
    ("KeepAliveTime", 300000, False, "KeepAliveTime 300,000"),
    ("NoNameReleaseOnDemand", 1, False, "NoNameReleaseOnDemand 1"),
]


def w54(section: Section, _: ParsedLog) -> Judgement:
    missing = [
        label
        for key, wanted, at_least, label in DOS_KEYS
        if (value := int_or_none(_value(section, key))) is None
        or (value < wanted if at_least else value != wanted)
    ]
    if missing:
        return vulnerable("DoS 방어 레지스트리 미설정: " + ", ".join(missing))
    return good("DoS 공격 방어 레지스트리 4개 값이 모두 설정되어 있습니다")


def w55(_: Section, log: ParsedLog) -> Judgement:
    value = _flag(log, "AddPrinterDrivers")
    if value is None or value == 1:
        suffix = "" if value is not None else "(정책 미정의, 서버 기본값 사용)"
        return good(f"'사용자가 프린터 드라이버를 설치할 수 없게 함' 정책이 사용입니다{suffix}")
    return vulnerable("'사용자가 프린터 드라이버를 설치할 수 없게 함' 정책이 사용 안 함입니다")


def w56(_: Section, log: ParsedLog) -> Judgement:
    forced = _flag(log, "EnableForcedLogOff")
    idle = _flag(log, "AutoDisconnect")
    forced = 1 if forced is None else forced  # 기본값: 사용
    idle = 15 if idle is None else idle  # 기본값: 15분
    if forced == 1 and 0 <= idle <= 15:
        return good(f"로그온 시간 만료 시 연결 끊기 사용, SMB 유휴 세션 {idle}분 후 중단")
    problems = []
    if forced != 1:
        problems.append("'로그온 시간이 만료되면 클라이언트 연결 끊기' 사용 안 함")
    if not 0 <= idle <= 15:
        problems.append(f"유휴 시간 {idle}분(15분 이하 필요)")
    return vulnerable("SMB 세션 중단 설정 미흡: " + ", ".join(problems))


def w57(_: Section, log: ParsedLog) -> Judgement:
    caption = (_policy(log, "LegalNoticeCaption") or "").strip().strip('"')
    text = (_policy(log, "LegalNoticeText") or "").strip().strip('"')
    if caption and text:
        return good("로그온 경고 메시지 제목과 내용이 설정되어 있습니다")
    return vulnerable("로그온 경고 메시지 제목 또는 내용이 설정되어 있지 않습니다")


def w58(section: Section, _: ParsedLog) -> Judgement:
    homes = _entries(section, "HOME_DIR")
    open_homes = [h["HOME_DIR"] for h in homes if h.get("EVERYONE") == "True"]
    if open_homes:
        return vulnerable(f"Everyone 권한이 있는 사용자 홈 디렉터리: {_listing(open_homes, 4)}")
    return good(f"사용자 홈 디렉터리 {len(homes)}개에 Everyone 권한이 없습니다")


def w59(_: Section, log: ParsedLog) -> Judgement:
    level = _flag(log, "LmCompatibilityLevel")
    if level is None:
        return good(
            "LAN Manager 인증 수준 정책이 정의되지 않아 기본값(NTLMv2 응답만 보냄)을 사용합니다"
        )
    if level >= 3:
        return good(f"LAN Manager 인증 수준이 {level}(NTLMv2 응답만 보냄 이상)입니다")
    return vulnerable(f"LAN Manager 인증 수준이 {level}로 LM·NTLM 응답을 보냅니다")


def w60(_: Section, log: ParsedLog) -> Judgement:
    off = [
        key
        for key in ("RequireSignOrSeal", "SealSecureChannel", "SignSecureChannel")
        if (value := _flag(log, key)) is not None and value != 1
    ]
    if off:
        return vulnerable("보안 채널 데이터 암호화·서명 정책 중 사용 안 함: " + ", ".join(off))
    return good("보안 채널 데이터 디지털 암호화·서명 정책 3개가 모두 사용입니다")


def w61(section: Section, _: ParsedLog) -> Judgement:
    volumes = _entries(section, "VOLUME")
    if not volumes:
        return vulnerable("파일 시스템 형식을 확인하지 못했습니다(수동 확인 필요)")
    fat = [
        f"{v['VOLUME']}:({v.get('FS')})"
        for v in volumes
        if v.get("FS", "").upper() not in ("NTFS", "REFS")
    ]
    if fat:
        return vulnerable(f"NTFS 가 아닌 파일 시스템을 사용합니다: {', '.join(fat)}")
    return good(f"고정 디스크 {len(volumes)}개 모두 NTFS(ReFS)를 사용합니다")


def w62(section: Section, _: ParsedLog) -> Judgement:
    items = [s["STARTUP"] for s in _entries(section, "STARTUP")]
    if items:
        return vulnerable(
            f"시작 프로그램 {len(items)}개({_listing(items, 4)}) — "
            "정기 검토 후 불필요하면 제거하고, "
            "필요한 항목이면 사유와 함께 판정을 변경하세요"
        )
    return good("등록된 시작 프로그램이 없습니다")


def w63(section: Section, log: ParsedLog) -> Judgement:
    if _value(section, "PART_OF_DOMAIN") != "True":
        return na("도메인에 가입하지 않아 Kerberos 시간 동기화 정책이 해당되지 않습니다")
    skew = _flag(log, "MaxClockSkew")
    if skew is None:
        return good("Kerberos 시계 동기화 최대 허용 오차가 기본값(5분)입니다")
    if skew <= 5:
        return good(f"Kerberos 시계 동기화 최대 허용 오차가 {skew}분입니다")
    return vulnerable(f"Kerberos 시계 동기화 최대 허용 오차가 {skew}분으로 5분을 넘습니다")


def w64(section: Section, _: ParsedLog) -> Judgement:
    profiles = _entries(section, "FIREWALL")
    if not profiles:
        return vulnerable("Windows 방화벽 상태를 확인하지 못했습니다(수동 확인 필요)")
    off = [p["FIREWALL"] for p in profiles if p.get("ENABLED") != "True"]
    if off:
        return vulnerable(f"Windows 방화벽이 꺼진 프로필: {', '.join(off)}")
    return good("Windows 방화벽이 모든 프로필(도메인·개인·공용)에서 사용입니다")


MEDIUM_LOW_RULES: list[Rule] = [
    Rule("W-07", "WIN-SECURITY_POLICY", w07, V10),
    Rule("W-08", "WIN-SECURITY_POLICY", w08, V10),
    Rule("W-10", "WIN-SECURITY_POLICY", w10, V10),
    Rule("W-11", "WIN-SECURITY_POLICY", w11, V12),
    Rule("W-12", "WIN-SECURITY_POLICY", w12, V10),
    Rule("W-13", "WIN-SECURITY_POLICY", w13, V10),
    Rule("W-14", "WIN-HARDENING", w14, V12),
    Rule("W-28", "WIN-REMOTE_ACCESS", w28, V10),
    Rule("W-29", "WIN-HARDENING", w29, V12),
    Rule("W-30", "WIN-HARDENING", w30, V12),
    Rule("W-31", "WIN-HARDENING", w31, V12),
    Rule("W-32", "WIN-DNS", w32, V12),
    Rule("W-33", "WIN-IIS_FTP", w33, V12),
    Rule("W-34", "WIN-HARDENING", w34, V12),
    Rule("W-35", "WIN-HARDENING", w35, V12),
    Rule("W-36", "WIN-HARDENING", w36, V12),
    Rule("W-37", "WIN-HARDENING", w37, V12),
    Rule("W-40", "WIN-SECURITY_POLICY", w40, V12),
    Rule("W-41", "WIN-HARDENING", w41, V12),
    Rule("W-42", "WIN-EVENTLOG", w42, V10),
    Rule("W-43", "WIN-HARDENING", w43, V12),
    Rule("W-54", "WIN-HARDENING", w54, V12),
    Rule("W-55", "WIN-SECURITY_POLICY", w55, V12),
    Rule("W-56", "WIN-SECURITY_POLICY", w56, V12),
    Rule("W-57", "WIN-SECURITY_POLICY", w57, V10),
    Rule("W-58", "WIN-HARDENING", w58, V12),
    Rule("W-59", "WIN-SECURITY_POLICY", w59, V12),
    Rule("W-60", "WIN-SECURITY_POLICY", w60, V12),
    Rule("W-61", "WIN-HARDENING", w61, V12),
    Rule("W-62", "WIN-HARDENING", w62, V12),
    Rule("W-63", "WIN-HARDENING", w63, V12),
    Rule("W-64", "WIN-HARDENING", w64, V12),
]

"""KISA 2026 Windows 서버 '상' 항목 판정 규칙 (kisa_check_windows.bat).

항목마다 필요한 구간과, 그 근거를 수집하기 시작한 스크립트 버전(since)을 둔다.
업무상 필요 여부처럼 자동으로 알 수 없는 부분은 객관적 기준(예: 90일 미접속)으로 판정하고,
예외는 사유와 함께 판정을 변경하도록 안내한다.
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
from modules.parser.log_parser import ParsedLog, Section

V10 = (1, 0, 0)
V11 = (1, 1, 0)
UNUSED_DAYS = 90
PATCH_DAYS = 60
SIGNATURE_DAYS = 7


# --- 공통 -------------------------------------------------------------------------------------


def _policy(log: ParsedLog, key: str) -> str | None:
    """보안 정책(secedit) 값. 레지스트리 값('4,1')은 쉼표 뒤 값을 돌려준다."""
    section = log.sections.get("WIN-SECURITY_POLICY")
    if section is None:
        return None
    for line in section.lines:
        match = re.match(r"^\s*([^=]+?)\s*=\s*(.*)$", line)
        if match and (match.group(1) == key or match.group(1).endswith("\\" + key)):
            value = match.group(2).strip()
            if "\\" in match.group(1) and "," in value:
                value = value.split(",", 1)[1]
            return value.strip().strip('"')
    return None


def _value(section: Section, key: str) -> str | None:
    values = section.values(key)
    return values[0] if values else None


def _services(log: ParsedLog) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for name in ("WIN-SERVICES", "WIN-IIS_FTP"):
        section = log.sections.get(name)
        for line in section.lines if section else []:
            fields = kv(line)
            if "SERVICE" in fields:
                result[fields["SERVICE"]] = fields
    return result


def _running(log: ParsedLog, *names: str) -> list[str]:
    services = _services(log)
    return [n for n in names if services.get(n, {}).get("STATUS") == "Running"]


def _entries(section: Section, key: str) -> list[dict[str, str]]:
    return [kv(line) for line in section.lines if line.startswith(f"{key}=")]


# --- 계정 관리 ----------------------------------------------------------------------------------


def w03(section: Section, _: ParsedLog) -> Judgement:
    accounts = _entries(section, "ACCOUNT")
    if not accounts:
        return vulnerable("로컬 계정 목록을 확인하지 못했습니다(수동 확인 필요)")
    unused: list[str] = []
    for account in accounts:
        if account.get("ENABLED") != "True":
            continue
        days = account.get("LAST_LOGON_DAYS", "")
        if days == "never" or (int_or_none(days) or 0) > UNUSED_DAYS:
            label = "로그인 기록 없음" if days == "never" else f"{days}일 미접속"
            unused.append(f"{account['ACCOUNT']}({label})")
    if unused:
        return vulnerable(
            f"{UNUSED_DAYS}일 넘게 사용하지 않은 활성 계정: {', '.join(unused)} "
            "— 필요한 계정이면 사유와 함께 판정을 변경하세요"
        )
    enabled = sum(1 for a in accounts if a.get("ENABLED") == "True")
    return good(f"활성 계정 {enabled}개 모두 최근 {UNUSED_DAYS}일 안에 사용되었습니다")


def w06(section: Section, _: ParsedLog) -> Judgement:
    if section.values("ADMIN_MEMBER_ERROR"):
        return vulnerable("Administrators 그룹 구성원을 확인하지 못했습니다(수동 확인 필요)")
    members = [m["ADMIN_MEMBER"] for m in _entries(section, "ADMIN_MEMBER")]
    if not members:
        return vulnerable("Administrators 그룹 구성원을 확인하지 못했습니다(수동 확인 필요)")
    if len(members) <= 1:
        return good(f"Administrators 그룹 구성원이 {len(members)}명입니다")
    return vulnerable(
        f"Administrators 그룹 구성원이 {len(members)}명입니다({', '.join(members)}). "
        "불필요한 관리자가 없다면 사유와 함께 판정을 변경하세요"
    )


def w09(_: Section, log: ParsedLog) -> Judgement:
    complexity = int_or_none(_policy(log, "PasswordComplexity"))
    length = int_or_none(_policy(log, "MinimumPasswordLength"))
    max_age = int_or_none(_policy(log, "MaximumPasswordAge"))
    min_age = int_or_none(_policy(log, "MinimumPasswordAge"))
    history = int_or_none(_policy(log, "PasswordHistorySize"))
    if None in (complexity, length, max_age, min_age, history):
        return vulnerable("비밀번호 정책 일부를 확인하지 못했습니다(수동 확인 필요)")
    missing: list[str] = []
    if complexity != 1:
        missing.append("복잡성 사용")
    if (length or 0) < 8:
        missing.append(f"최소 길이 8자(현재 {length})")
    if not 1 <= (max_age or 0) <= 90:
        missing.append(f"최대 사용 기간 90일(현재 {max_age})")
    if (min_age or 0) < 1:
        missing.append(f"최소 사용 기간 1일(현재 {min_age})")
    if (history or 0) < 4:
        missing.append(f"최근 암호 4개 기억(현재 {history})")
    if missing:
        return vulnerable("비밀번호 관리 정책 미흡: " + ", ".join(missing))
    return good("복잡성·최소 길이·최대/최소 사용 기간·암호 기억 정책이 모두 적용되어 있습니다")


# --- 서비스 관리 --------------------------------------------------------------------------------


def w15(section: Section, _: ParsedLog) -> Judgement:
    value = _value(section, "ForceKeyProtection")
    if value == "2":
        return good("사용자 개인 키를 사용할 때마다 암호를 입력하도록 설정되어 있습니다")
    if value is None:
        return vulnerable("개인 키 보호 정책을 확인하지 못했습니다(수동 확인 필요)")
    label = "미설정" if value == "NOT_SET" else value
    return vulnerable(f"강력한 키 보호 정책이 '매번 암호 입력'(2)이 아닙니다(현재 {label})")


def w16(section: Section, _: ParsedLog) -> Judgement:
    if section.command_output("Get-SmbShareAccess") is None:
        return vulnerable("공유 폴더 권한을 확인하지 못했습니다(수동 확인 필요)")
    shares = _entries(section, "SHARE")
    everyone = sorted(
        {
            s["SHARE"]
            for s in shares
            if s.get("ACCOUNT", "").lower() == "everyone" and s.get("TYPE") == "Allow"
        }
    )
    if everyone:
        return vulnerable(f"Everyone 권한이 있는 공유 폴더: {', '.join(everyone)}")
    if not shares:
        return good("일반 공유 폴더가 없습니다")
    return good("일반 공유 폴더 접근 권한에 Everyone 이 없습니다")


_DEFAULT_SHARE = re.compile(r"^([A-Z]\$|ADMIN\$)\s", re.IGNORECASE)


def w17(section: Section, _: ParsedLog) -> Judgement:
    shares = [
        m.group(1).upper()
        for line in section.command_output("net share") or []
        if (m := _DEFAULT_SHARE.match(line.strip()))
    ]
    auto = _value(section, "AutoShareServer")
    problems: list[str] = []
    if auto != "0":
        problems.append(f"AutoShareServer={auto or '미설정(기본 1)'}")
    if shares:
        problems.append(f"기본 공유 {', '.join(shares)}")
    if problems:
        return vulnerable("하드디스크 기본 공유가 남아 있습니다: " + ", ".join(problems))
    return good("AutoShareServer=0 이며 기본 공유(C$·ADMIN$ 등)가 없습니다")


# 2026 가이드의 '일반적으로 불필요한 서비스' 중 현재 Windows 서버에서 운영에 필수가 아닌 서비스.
# Cryptographic Services·DHCP Client·DNS Client·Automatic Updates 는 최신 Windows 에서
# OS 기능·패치에 필요해 자동 판정에서 제외하고, 원격 레지스트리는 W-44 에서 따로 본다.
UNNEEDED_SERVICES = {
    "Alerter": "Alerter",
    "ClipSrv": "Clipbook",
    "Browser": "Computer Browser",
    "TrkWks": "Distributed Link Tracking Client",
    "TrkSvr": "Distributed Link Tracking Server",
    "WerSvc": "Windows Error Reporting",
    "HidServ": "Human Interface Device Access",
    "ImapiService": "IMAPI CD-Burning COM",
    "Irmon": "Infrared Monitor",
    "Messenger": "Messenger",
    "mnmsrvc": "NetMeeting Remote Desktop Sharing",
    "WmdmPmSN": "Portable Media Serial Number",
    "Spooler": "Print Spooler",
    "simptcp": "Simple TCP/IP Services",
    "upnphost": "UPnP Device Host",
    "WZCSVC": "Wireless Zero Configuration",
}


def w18(_: Section, log: ParsedLog) -> Judgement:
    running = _running(log, *UNNEEDED_SERVICES)
    if running:
        names = ", ".join(f"{UNNEEDED_SERVICES[n]}({n})" for n in running)
        return vulnerable(
            f"일반적으로 불필요한 서비스가 구동 중입니다: {names} "
            "— 업무상 필요하면 사유와 함께 판정을 변경하세요"
        )
    return good("일반적으로 불필요한 서비스가 중지되어 있습니다")


def w19(_: Section, log: ParsedLog) -> Judgement:
    if _running(log, "W3SVC"):
        return vulnerable(
            "IIS 웹 서비스(W3SVC)가 구동 중입니다. 업무상 필요하면 사유와 함께 판정을 변경하세요"
        )
    return good("IIS 웹 서비스를 사용하지 않습니다")


def w20(section: Section, _: ParsedLog) -> Judgement:
    adapters = _entries(section, "NETBIOS_ADAPTER")
    if not adapters:
        return vulnerable("NetBIOS 바인딩 설정을 확인하지 못했습니다(수동 확인 필요)")
    enabled = [a["NETBIOS_ADAPTER"] for a in adapters if a.get("OPTION") != "2"]
    if enabled:
        return vulnerable(
            f"NetBIOS over TCP/IP 가 해제되지 않은 네트워크 어댑터 {len(enabled)}개"
            f"(인덱스 {', '.join(enabled)})"
        )
    return good("모든 네트워크 어댑터에서 NetBIOS over TCP/IP 가 해제되어 있습니다")


def _ftp_in_use(section: Section, log: ParsedLog) -> bool:
    return bool(_running(log, "FTPSVC", "MSFTPSVC")) or bool(_entries(section, "FTP_SITE"))


def w21(section: Section, log: ParsedLog) -> Judgement:
    if not _ftp_in_use(section, log):
        return good("FTP 서비스를 사용하지 않습니다")
    sites = _entries(section, "FTP_SITE")
    plain = [
        s["FTP_SITE"]
        for s in sites
        if s.get("SSL_CONTROL") != "SslRequire" or s.get("SSL_DATA") != "SslRequire"
    ]
    if not sites:
        return vulnerable(
            "FTP 서비스가 구동 중이나 사이트 설정을 확인하지 못했습니다(수동 확인 필요)"
        )
    if plain:
        return vulnerable(f"암호화(SSL)를 요구하지 않는 FTP 사이트: {', '.join(plain)}")
    return good("모든 FTP 사이트가 제어·데이터 채널에 SSL 을 요구합니다(FTPS)")


def w22(section: Section, log: ParsedLog) -> Judgement:
    if not _ftp_in_use(section, log):
        return na("FTP 서비스를 사용하지 않습니다")
    sites = _entries(section, "FTP_SITE")
    if not sites:
        return vulnerable("FTP 홈 디렉터리 권한을 확인하지 못했습니다(수동 확인 필요)")
    shared = [s["FTP_SITE"] for s in sites if s.get("EVERYONE") == "True"]
    if shared:
        return vulnerable(f"FTP 홈 디렉터리에 Everyone 권한이 있습니다: {', '.join(shared)}")
    return good("FTP 홈 디렉터리에 Everyone 권한이 없습니다")


def w23(section: Section, log: ParsedLog) -> Judgement:
    if not _ftp_in_use(section, log):
        return good("FTP 공유 서비스를 사용하지 않습니다")
    sites = _entries(section, "FTP_SITE")
    if not sites:
        return vulnerable("FTP 익명 인증 설정을 확인하지 못했습니다(수동 확인 필요)")
    anonymous = [s["FTP_SITE"] for s in sites if s.get("ANONYMOUS") == "True"]
    if anonymous:
        return vulnerable(f"익명 인증을 허용하는 FTP 사이트: {', '.join(anonymous)}")
    return good("FTP 익명 인증이 사용 안 함으로 설정되어 있습니다")


def w24(section: Section, log: ParsedLog) -> Judgement:
    if not _ftp_in_use(section, log):
        return na("FTP 서비스를 사용하지 않습니다")
    sites = _entries(section, "FTP_SITE")
    if not sites:
        return vulnerable("FTP 접근 제어 설정을 확인하지 못했습니다(수동 확인 필요)")
    open_sites = [s["FTP_SITE"] for s in sites if s.get("ALLOW_UNLISTED") != "False"]
    if open_sites:
        return vulnerable(f"IP 주소 접근 제한이 없는 FTP 사이트: {', '.join(open_sites)}")
    return good("모든 FTP 사이트가 지정된 IP 주소에서만 접속을 허용합니다")


def w25(section: Section, log: ParsedLog) -> Judgement:
    if not _running(log, "DNS"):
        return good("DNS 서비스가 비활성화되어 있습니다")
    if _value(section, "DNS_ZONES") == "unavailable":
        return vulnerable("DNS 영역 전송 설정을 확인하지 못했습니다(수동 확인 필요)")
    transfers = section.values("DNS_ZONE_TRANSFER")
    open_zones = sum(1 for value in transfers if value == "0")
    if open_zones:
        return vulnerable(f"모든 서버로 영역 전송을 허용하는 DNS 영역이 {open_zones}개 있습니다")
    return good("DNS 영역 전송이 허용 안 함 또는 지정된 서버로 제한되어 있습니다")


def w26(_: Section, log: ParsedLog) -> Judgement:
    if not _running(log, "W3SVC"):
        return good("IIS 를 사용하지 않습니다")
    distro = " ".join(log.info.get("DISTRO", []))
    version = re.search(r"\b(\d+)\.(\d+)\.\d+\s*$", distro)
    if version and int(version.group(1)) >= 6:
        return good(f"Windows 2008 이상({distro.strip()})으로 RDS 취약점이 해당되지 않습니다")
    iis = log.sections.get("WIN-IIS_FTP")
    if iis is not None and _value(iis, "MSADC_VDIR") == "False":
        return good("기본 웹 사이트에 MSADC 가상 디렉터리가 없습니다")
    return vulnerable("IIS 를 사용하며 RDS(MSADC) 제거 여부를 확인하지 못했습니다(수동 확인 필요)")


def _hotfix_days(section: Section) -> tuple[str, int | None]:
    line = next((line for line in section.lines if line.startswith("LAST_HOTFIX=")), "")
    fields = kv(line)
    return fields.get("LAST_HOTFIX", ""), int_or_none(fields.get("DAYS_AGO"))


def w27(section: Section, log: ParsedLog) -> Judgement:
    registry = log.sections.get("WIN-REGISTRY")
    build = (
        f"{_value(registry, 'CurrentBuild')}.{_value(registry, 'UBR')}" if registry else "확인 불가"
    )
    hotfix, days = _hotfix_days(section)
    if days is None:
        return vulnerable(f"OS Build {build}, 최근 업데이트 설치일을 확인하지 못했습니다")
    if days > PATCH_DAYS:
        return vulnerable(
            f"OS Build {build}, 마지막 업데이트({hotfix})가 {days}일 전으로 "
            f"최신 Build 가 아닐 가능성이 높습니다({PATCH_DAYS}일 기준)"
        )
    return good(
        f"OS Build {build}, 최근 {days}일 전 업데이트({hotfix}) 적용. "
        "Build 적용 절차 수립 여부는 별도로 확인하세요"
    )


def w38(section: Section, _: ParsedLog) -> Judgement:
    hotfix, days = _hotfix_days(section)
    if hotfix == "none":
        return vulnerable("설치된 보안 업데이트 기록이 없습니다")
    if days is None:
        return vulnerable("최근 보안 업데이트 설치일을 확인하지 못했습니다(수동 확인 필요)")
    if days > PATCH_DAYS:
        return vulnerable(
            f"마지막 보안 업데이트({hotfix})가 {days}일 전입니다({PATCH_DAYS}일 기준)"
        )
    return good(f"최근 {days}일 전에 보안 업데이트({hotfix})를 설치했습니다")


def w39(section: Section, _: ParsedLog) -> Judgement:
    age = int_or_none(_value(section, "DefenderSignatureAge"))
    enabled = _value(section, "DefenderAntivirusEnabled") == "True"
    if enabled and age is not None:
        if age <= SIGNATURE_DAYS:
            return good(f"Microsoft Defender 엔진·서명이 {age}일 전에 업데이트되었습니다")
        return vulnerable(f"Microsoft Defender 서명이 {age}일 전으로 오래되었습니다")
    others = [e["AV_SERVICE"] for e in _entries(section, "AV_SERVICE")]
    if others:
        return vulnerable(
            f"타사 백신({', '.join(others)})의 엔진 업데이트 여부를 자동으로 확인할 수 없습니다"
            "(수동 확인 필요)"
        )
    return vulnerable(
        "백신 엔진 업데이트 상태를 확인하지 못했습니다(백신 미설치 또는 수동 확인 필요)"
    )


def w44(_: Section, log: ParsedLog) -> Judgement:
    service = _services(log).get("RemoteRegistry")
    if service is None:
        return good("원격 레지스트리 서비스가 없습니다")
    if service.get("STATUS") == "Running" or service.get("START") == "Automatic":
        return vulnerable(
            f"원격 레지스트리 서비스가 사용 중입니다(상태 {service.get('STATUS')}, "
            f"시작 유형 {service.get('START')})"
        )
    return good(f"원격 레지스트리 서비스가 중지되어 있습니다(시작 유형 {service.get('START')})")


def w45(section: Section, log: ParsedLog) -> Judgement:
    if _value(section, "AMServiceEnabled") == "True":
        return good("Microsoft Defender 백신이 설치되어 동작 중입니다")
    patch = log.sections.get("WIN-PATCH_AV")
    others = [e["AV_SERVICE"] for e in _entries(patch, "AV_SERVICE")] if patch else []
    if others:
        return good(f"백신 프로그램이 설치되어 있습니다: {', '.join(others)}")
    return vulnerable("백신 프로그램을 확인하지 못했습니다(미설치 또는 수동 확인 필요)")


_SAM_ALLOWED = re.compile(r"(\\|^)(Administrators|SYSTEM)$", re.IGNORECASE)


def w46(section: Section, _: ParsedLog) -> Judgement:
    aces = _entries(section, "SAM_ACE")
    if not aces:
        return vulnerable("SAM 파일 접근 권한을 확인하지 못했습니다(수동 확인 필요)")
    others = sorted(
        {
            a["SAM_ACE"]
            for a in aces
            if a.get("TYPE") == "Allow" and not _SAM_ALLOWED.search(a["SAM_ACE"])
        }
    )
    if others:
        return vulnerable(
            f"SAM 파일에 Administrators·SYSTEM 외 권한이 있습니다: {', '.join(others)}"
        )
    return good("SAM 파일 접근 권한이 Administrators·SYSTEM 에만 있습니다")


def w47(section: Section, log: ParsedLog) -> Judgement:
    def pick(name: str) -> str | None:
        policy = _value(section, f"Policy{name}")
        return policy if policy not in (None, "NOT_SET") else _value(section, name)

    active, secure, timeout = (
        pick("ScreenSaveActive"),
        pick("ScreenSaverIsSecure"),
        pick("ScreenSaveTimeOut"),
    )
    seconds = int_or_none(timeout)
    if active == "1" and secure == "1" and seconds is not None and 0 < seconds <= 600:
        return good(f"화면 보호기 {seconds // 60}분, 해제 시 암호 사용으로 설정되어 있습니다")
    inactivity = int_or_none(_policy(log, "InactivityTimeoutSecs"))
    if inactivity is not None and 0 < inactivity <= 600:
        return good(f"컴퓨터 비활성 한도 {inactivity}초 후 화면이 잠기도록 설정되어 있습니다")
    problems = []
    if active != "1":
        problems.append("화면 보호기 미사용")
    if secure != "1":
        problems.append("해제 시 암호 미사용")
    if seconds is None or not 0 < seconds <= 600:
        problems.append(f"대기 시간 {timeout or '미설정'}초(600초 이하 필요)")
    return vulnerable("화면 보호기 설정 미흡: " + ", ".join(problems))


def _flag(log: ParsedLog, key: str) -> int | None:
    return int_or_none(_policy(log, key))


def w48(_: Section, log: ParsedLog) -> Judgement:
    value = _flag(log, "ShutdownWithoutLogon")
    if value is None:
        return vulnerable("'로그온하지 않고 시스템 종료 허용' 정책을 확인하지 못했습니다")
    if value == 0:
        return good("'로그온하지 않고 시스템 종료 허용'이 사용 안 함입니다")
    return vulnerable("'로그온하지 않고 시스템 종료 허용'이 사용으로 되어 있습니다")


ADMINISTRATORS_SID = "*S-1-5-32-544"


def w49(_: Section, log: ParsedLog) -> Judgement:
    value = _policy(log, "SeRemoteShutdownPrivilege")
    if value is None:
        return good("'원격 시스템에서 강제로 시스템 종료' 권한이 부여된 계정이 없습니다")
    holders = [v.strip() for v in value.split(",") if v.strip()]
    others = [h for h in holders if h not in (ADMINISTRATORS_SID, "Administrators")]
    if others:
        return vulnerable(
            f"원격 강제 종료 권한에 Administrators 외 계정·그룹이 있습니다: {', '.join(others)}"
        )
    return good("원격 강제 종료 권한이 Administrators 에만 있습니다")


def w50(_: Section, log: ParsedLog) -> Judgement:
    value = _flag(log, "CrashOnAuditFail")
    if value is None:
        return vulnerable(
            "'보안 감사를 로그할 수 없는 경우 즉시 시스템 종료' 정책을 확인하지 못했습니다"
        )
    if value == 0:
        return good("'보안 감사를 로그할 수 없는 경우 즉시 시스템 종료'가 사용 안 함입니다")
    return vulnerable("'보안 감사를 로그할 수 없는 경우 즉시 시스템 종료'가 사용으로 되어 있습니다")


def w51(_: Section, log: ParsedLog) -> Judgement:
    shares, sam = _flag(log, "RestrictAnonymous"), _flag(log, "RestrictAnonymousSAM")
    if shares is None or sam is None:
        return vulnerable("익명 열거 제한 정책을 확인하지 못했습니다(수동 확인 필요)")
    problems = []
    if sam != 1:
        problems.append("SAM 계정 익명 열거 허용")
    if shares < 1:
        problems.append("SAM 계정과 공유 익명 열거 허용")
    if problems:
        return vulnerable("익명 열거가 허용되어 있습니다: " + ", ".join(problems))
    return good("'SAM 계정과 공유의 익명 열거 허용 안 함'이 사용으로 설정되어 있습니다")


def w52(section: Section, _: ParsedLog) -> Judgement:
    values = section.values("AutoAdminLogon")
    if not values:
        return vulnerable("자동 로그온 설정을 확인하지 못했습니다(수동 확인 필요)")
    value = values[0].strip()
    if value == "1":
        return vulnerable("자동 로그온(AutoAdminLogon=1)이 설정되어 있습니다")
    return good("자동 로그온(AutoAdminLogon)이 설정되어 있지 않습니다")


def w53(_: Section, log: ParsedLog) -> Judgement:
    value = _policy(log, "AllocateDASD")
    if value is None:
        return good(
            "'이동식 미디어 포맷 및 꺼내기 허용' 정책이 정의되지 않아 Administrators 만 허용됩니다"
        )
    if value == "0":
        return good("'이동식 미디어 포맷 및 꺼내기 허용'이 Administrators 로 설정되어 있습니다")
    label = {"1": "Administrators 및 Power Users", "2": "Administrators 및 Interactive Users"}
    return vulnerable(f"'이동식 미디어 포맷 및 꺼내기 허용'이 {label.get(value, value)} 입니다")


HIGH_RULES: list[Rule] = [
    Rule("W-03", "WIN-ACCOUNTS", w03, V11),
    Rule("W-06", "WIN-ACCOUNTS", w06, V11),
    Rule("W-09", "WIN-SECURITY_POLICY", w09, V10),
    Rule("W-15", "WIN-REGISTRY", w15, V11),
    Rule("W-16", "WIN-SHARE_ACL", w16, V11),
    Rule("W-17", "WIN-SHARES", w17, V10),
    Rule("W-18", "WIN-SERVICES", w18, V11),
    Rule("W-19", "WIN-SERVICES", w19, V10),
    Rule("W-20", "WIN-REGISTRY", w20, V11),
    Rule("W-21", "WIN-IIS_FTP", w21, V11),
    Rule("W-22", "WIN-IIS_FTP", w22, V11),
    Rule("W-23", "WIN-IIS_FTP", w23, V11),
    Rule("W-24", "WIN-IIS_FTP", w24, V11),
    Rule("W-25", "WIN-DNS", w25, V11),
    Rule("W-26", "WIN-SERVICES", w26, V10),
    Rule("W-27", "WIN-PATCH_AV", w27, V11),
    Rule("W-38", "WIN-PATCH_AV", w38, V11),
    Rule("W-39", "WIN-PATCH_AV", w39, V11),
    Rule("W-44", "WIN-SERVICES", w44, V10),
    Rule("W-45", "WIN-ANTIVIRUS", w45, V10),
    Rule("W-46", "WIN-SHARE_ACL", w46, V11),
    Rule("W-47", "WIN-REGISTRY", w47, V11),
    Rule("W-48", "WIN-SECURITY_POLICY", w48, V11),
    Rule("W-49", "WIN-SECURITY_POLICY", w49, V10),
    Rule("W-50", "WIN-SECURITY_POLICY", w50, V11),
    Rule("W-51", "WIN-SECURITY_POLICY", w51, V10),
    Rule("W-52", "WIN-REMOTE_ACCESS", w52, V10),
    Rule("W-53", "WIN-SECURITY_POLICY", w53, V11),
]

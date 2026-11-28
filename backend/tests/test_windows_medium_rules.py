"""KISA 2026 Windows 중요도 '중'·'하' 항목 규칙의 경계: 강화 fixture 를 한 군데씩 바꿔 확인한다."""

from pathlib import Path

import pytest

from modules.compliance.guideline_mapper import map_log
from modules.parser.log_parser import parse_log

HARDENED = (
    (Path(__file__).with_name("fixtures") / "windows_hardened.txt")
    .read_text(encoding="utf-8")
    .replace("\r\n", "\n")
)
LSA = "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\"
SYS = "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"
LANMAN = "MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\"
NETLOGON = "MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\"
SERVICES_END = "==== WIN-SERVICES END ===="


def judged(text: str) -> dict[str, tuple[str, str]]:
    mapped = map_log(parse_log(text))
    assert mapped.errors == []
    return {r.item_code: (r.status, r.reason) for r in mapped.results}


def replaced(old: str, new: str, text: str = HARDENED) -> str:
    assert old in text, f"fixture 에 '{old}' 가 없습니다"
    return text.replace(old, new, 1)


def with_service(line: str, text: str = HARDENED) -> str:
    return replaced(SERVICES_END, f"{line}\n{SERVICES_END}", text)


@pytest.mark.parametrize(
    ("item", "old", "new", "expected"),
    [
        (
            "W-07",
            "EveryoneIncludesAnonymous=4,0",
            "EveryoneIncludesAnonymous=4,1",
            "vulnerable",
        ),
        ("W-08", "LockoutDuration = 60", "LockoutDuration = 30", "vulnerable"),
        ("W-08", "ResetLockoutCount = 60", "ResetLockoutCount = 59", "vulnerable"),
        ("W-10", "DontDisplayLastUserName=4,1", "DontDisplayLastUserName=4,0", "vulnerable"),
        (
            "W-11",
            "SeInteractiveLogonRight = *S-1-5-32-544",
            "SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545",
            "vulnerable",
        ),
        (
            "W-11",
            "SeInteractiveLogonRight = *S-1-5-32-544",
            "SeInteractiveLogonRight = *S-1-5-32-544,IUSR",
            "good",
        ),
        ("W-12", "LSAAnonymousNameLookup = 0", "LSAAnonymousNameLookup = 1", "vulnerable"),
        ("W-13", "LimitBlankPasswordUse=4,1", "LimitBlankPasswordUse=4,0", "vulnerable"),
        ("W-14", "RDP_MEMBER=WIN-SRV-02\\rdpops CLASS=User\n", "", "vulnerable"),
        ("W-14", "fDenyTSConnections=0", "fDenyTSConnections=1", "good"),  # RDP 미사용
        ("W-28", "MinEncryptionLevel=2", "MinEncryptionLevel=1", "vulnerable"),
        (
            "W-34",
            SERVICES_END,
            "SERVICE=TlntSvr STATUS=Running START=Manual\n" + SERVICES_END,
            "vulnerable",
        ),
        ("W-35", "$ ODBC system DSN\n", "$ ODBC system DSN\nODBC_DSN=LegacyERP\n", "vulnerable"),
        ("W-36", "PolicyMaxIdleTime=900000", "PolicyMaxIdleTime=3600000", "vulnerable"),
        ("W-36", "PolicyMaxIdleTime=900000", "PolicyMaxIdleTime=1800000", "good"),
        (
            "W-37",
            "(non-Microsoft)\n",
            "(non-Microsoft)\nTASK=\\Updater\\run.ps1 STATE=Ready\n",
            "vulnerable",
        ),
        ("W-40", "AuditPolicyChange = 3", "AuditPolicyChange = 1", "vulnerable"),
        ("W-40", "AuditDSAccess = 2", "AuditDSAccess = 3", "good"),
        ("W-40", "AuditAccountManage = 3", "AuditAccountManage = 1", "vulnerable"),
        ("W-41", "W32TimeType=NTP", "W32TimeType=NoSync", "vulnerable"),
        ("W-41", "NTP_SERVER_SET=True", "NTP_SERVER_SET=False", "vulnerable"),
        ("W-42", "maxSize: 20971520", "maxSize: 1052672", "vulnerable"),
        ("W-43", "LOGDIR_EVERYONE=False", "LOGDIR_EVERYONE=True", "vulnerable"),
        ("W-54", "KeepAliveTime=300000", "KeepAliveTime=7200000", "vulnerable"),
        ("W-54", "SynAttackProtect=1", "SynAttackProtect=2", "good"),
        ("W-55", "AddPrinterDrivers=4,1", "AddPrinterDrivers=4,0", "vulnerable"),
        (
            "W-56",
            LANMAN + "AutoDisconnect=4,15",
            LANMAN + "AutoDisconnect=4,30",
            "vulnerable",
        ),
        (
            "W-56",
            LANMAN + "EnableForcedLogOff=4,1",
            LANMAN + "EnableForcedLogOff=4,0",
            "vulnerable",
        ),
        (
            "W-57",
            SYS + 'LegalNoticeCaption=1,"경고"',
            SYS + 'LegalNoticeCaption=1,""',
            "vulnerable",
        ),
        ("W-58", "SrvOps01 EVERYONE=False", "SrvOps01 EVERYONE=True", "vulnerable"),
        ("W-59", LSA + "LmCompatibilityLevel=4,5", LSA + "LmCompatibilityLevel=4,2", "vulnerable"),
        ("W-59", LSA + "LmCompatibilityLevel=4,5\n", "", "good"),  # 미정의 = 기본값 3
        (
            "W-60",
            NETLOGON + "SealSecureChannel=4,1",
            NETLOGON + "SealSecureChannel=4,0",
            "vulnerable",
        ),
        ("W-61", "VOLUME=C FS=NTFS", "VOLUME=C FS=NTFS\nVOLUME=D FS=FAT32", "vulnerable"),
        (
            "W-62",
            "$ startup programs\n",
            "$ startup programs\nSTARTUP=Agent LOCATION=HKLM\\Run\n",
            "vulnerable",
        ),
        ("W-63", "PART_OF_DOMAIN=False", "PART_OF_DOMAIN=True", "good"),  # 기본 5분
        ("W-64", "FIREWALL=Public ENABLED=True", "FIREWALL=Public ENABLED=False", "vulnerable"),
    ],
)
def test_windows_medium_rule_boundaries(item: str, old: str, new: str, expected: str) -> None:
    status, reason = judged(replaced(old, new))[item]
    assert status == expected, reason


def test_snmp_rules() -> None:
    text = with_service("SERVICE=SNMP STATUS=Running START=Automatic")
    result = judged(text)
    assert [result[c][0] for c in ("W-29", "W-30", "W-31")] == ["vulnerable", "good", "vulnerable"]
    configured = replaced(
        "SNMP_PERMITTED_MANAGERS=0",
        "SNMP_COMMUNITY=MASKED STRENGTH=ok\nSNMP_PERMITTED_MANAGERS=2",
        text,
    )
    result = judged(configured)
    assert [result[c][0] for c in ("W-29", "W-30", "W-31")] == ["good", "good", "good"]
    public = replaced("SNMP_COMMUNITY=MASKED", "SNMP_COMMUNITY=public", configured)
    assert judged(public)["W-30"][0] == "vulnerable"


def test_dns_dynamic_update() -> None:
    text = with_service("SERVICE=DNS STATUS=Running START=Automatic")
    text = replaced("DNS_ZONES=unavailable", "DNS_ZONE_TRANSFER=3 DNS_ZONE_UPDATE=None", text)
    assert judged(text)["W-32"][0] == "good"
    secure = replaced("DNS_ZONE_UPDATE=None", "DNS_ZONE_UPDATE=Secure", text)
    assert judged(secure)["W-32"][0] == "vulnerable"


def test_banners() -> None:
    text = with_service("SERVICE=W3SVC STATUS=Running START=Automatic")
    assert judged(text)["W-33"][0] == "vulnerable"
    hidden = replaced("IIS_REMOVE_SERVER_HEADER=unknown", "IIS_REMOVE_SERVER_HEADER=True", text)
    assert judged(hidden)["W-33"][0] == "good"


def test_telnet_ntlm_only_is_good() -> None:
    text = with_service("SERVICE=TlntSvr STATUS=Running START=Manual")
    text = replaced("TelnetSecurityMechanism=NOT_SET", "TelnetSecurityMechanism=2", text)
    assert judged(text)["W-34"][0] == "good"


def test_domain_member_clock_skew() -> None:
    text = replaced("PART_OF_DOMAIN=False", "PART_OF_DOMAIN=True")
    text = replaced("AuditAccountLogon = 3\n", "AuditAccountLogon = 3\nMaxClockSkew = 10\n", text)
    assert judged(text)["W-63"][0] == "vulnerable"

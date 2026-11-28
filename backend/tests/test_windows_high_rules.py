"""KISA 2026 Windows '상' 항목 규칙의 경계: 강화 fixture 를 한 군데씩 바꿔 판정을 확인한다."""

from pathlib import Path

import pytest

from modules.compliance.guideline_mapper import map_log
from modules.parser.log_parser import parse_log

FIXTURES = Path(__file__).with_name("fixtures")
HARDENED = (FIXTURES / "windows_hardened.txt").read_text(encoding="utf-8").replace("\r\n", "\n")


def judged(text: str) -> dict[str, tuple[str, str]]:
    mapped = map_log(parse_log(text))
    assert mapped.errors == []
    return {r.item_code: (r.status, r.reason) for r in mapped.results}


def replaced(old: str, new: str) -> str:
    assert old in HARDENED, f"fixture 에 '{old}' 가 없습니다"
    return HARDENED.replace(old, new, 1)


ADMIN = "ADMIN_MEMBER=WIN-SRV-02\\SrvOps01 CLASS=User SOURCE=Local\n"
FTP = "IIS_MODULE=unavailable\n"
FTP_ON = "SERVICE=SharedAccess STATUS=Stopped START=Manual\n"
SITE = (
    "FTP_SITE=Files SSL_CONTROL=SslRequire SSL_DATA=SslRequire "
    "ANONYMOUS=False EVERYONE=False ALLOW_UNLISTED=False\n"
)
LSA = "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\"


@pytest.mark.parametrize(
    ("item", "old", "new", "expected"),
    [
        ("W-03", "RID=500 LAST_LOGON_DAYS=1", "RID=500 LAST_LOGON_DAYS=91", "vulnerable"),
        ("W-03", "RID=500 LAST_LOGON_DAYS=1", "RID=500 LAST_LOGON_DAYS=90", "good"),
        (
            "W-03",
            "ACCOUNT=DefaultAccount ENABLED=False",
            "ACCOUNT=DefaultAccount ENABLED=True",
            "vulnerable",
        ),
        (
            "W-06",
            ADMIN,
            ADMIN + "ADMIN_MEMBER=CORP\\Domain_Admins CLASS=Group SOURCE=ActiveDirectory\n",
            "vulnerable",
        ),
        ("W-06", ADMIN, "ADMIN_MEMBER_ERROR=InvalidOperationException\n", "vulnerable"),
        ("W-09", "MinimumPasswordLength = 8", "MinimumPasswordLength = 7", "vulnerable"),
        ("W-09", "MaximumPasswordAge = 90", "MaximumPasswordAge = 91", "vulnerable"),
        ("W-09", "MaximumPasswordAge = 90", "MaximumPasswordAge = 0", "vulnerable"),  # 만료 없음
        ("W-09", "PasswordComplexity = 1", "PasswordComplexity = 0", "vulnerable"),
        ("W-15", "ForceKeyProtection=2", "ForceKeyProtection=1", "vulnerable"),
        ("W-16", "ACCOUNT=BUILTIN\\Administrators", "ACCOUNT=Everyone", "vulnerable"),
        ("W-17", "AutoShareServer=0", "AutoShareServer=1", "vulnerable"),
        (
            "W-17",
            "IPC$ ",
            "D$           D:\\                             Default share\nIPC$ ",
            "vulnerable",
        ),
        ("W-18", "SERVICE=Browser STATUS=Stopped", "SERVICE=Browser STATUS=Running", "vulnerable"),
        ("W-19", FTP_ON, FTP_ON + "SERVICE=W3SVC STATUS=Running START=Automatic\n", "vulnerable"),
        ("W-20", "OPTION=2", "OPTION=1", "vulnerable"),
        ("W-21", FTP, SITE.replace("SSL_DATA=SslRequire", "SSL_DATA=SslAllow"), "vulnerable"),
        ("W-21", FTP, SITE, "good"),
        ("W-22", FTP, SITE.replace("EVERYONE=False", "EVERYONE=True"), "vulnerable"),
        ("W-22", FTP, SITE, "good"),
        ("W-23", FTP, SITE.replace("ANONYMOUS=False", "ANONYMOUS=True"), "vulnerable"),
        ("W-24", FTP, SITE.replace("ALLOW_UNLISTED=False", "ALLOW_UNLISTED=True"), "vulnerable"),
        ("W-24", FTP, SITE, "good"),
        ("W-27", "DAYS_AGO=45", "DAYS_AGO=61", "vulnerable"),
        ("W-38", "DAYS_AGO=45", "DAYS_AGO=120", "vulnerable"),
        ("W-38", "LAST_HOTFIX=KB5044281 DAYS_AGO=45", "LAST_HOTFIX=none", "vulnerable"),
        ("W-39", "DefenderSignatureAge=0", "DefenderSignatureAge=8", "vulnerable"),
        (
            "W-39",
            "DefenderAntivirusEnabled=True\nDefenderSignatureAge=0\n$ antivirus services\n",
            "$ antivirus services\nAV_SERVICE=V3_Service STATE=Running\n",
            "vulnerable",
        ),
        (
            "W-44",
            "SERVICE=RemoteRegistry STATUS=Stopped START=Disabled",
            "SERVICE=RemoteRegistry STATUS=Running START=Manual",
            "vulnerable",
        ),
        (
            "W-44",
            "SERVICE=RemoteRegistry STATUS=Stopped START=Disabled",
            "SERVICE=RemoteRegistry STATUS=Stopped START=Manual",
            "good",
        ),
        ("W-45", "AMServiceEnabled=True", "AMServiceEnabled=False", "vulnerable"),
        (
            "W-46",
            "SAM_ACE=NT_AUTHORITY\\SYSTEM",
            "SAM_ACE=BUILTIN\\Users RIGHTS=ReadAndExecute TYPE=Allow\nSAM_ACE=NT_AUTHORITY\\SYSTEM",
            "vulnerable",
        ),
        (
            "W-47",
            "ScreenSaveTimeOut=600",
            "ScreenSaveTimeOut=601",
            "good",
        ),  # 비활성 한도 600초로 보완
        ("W-48", "ShutdownWithoutLogon=4,0", "ShutdownWithoutLogon=4,1", "vulnerable"),
        (
            "W-49",
            "SeRemoteShutdownPrivilege = *S-1-5-32-544",
            "SeRemoteShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-549",
            "vulnerable",
        ),
        ("W-50", "CrashOnAuditFail=4,0", "CrashOnAuditFail=4,1", "vulnerable"),
        ("W-51", LSA + "RestrictAnonymous=4,1", LSA + "RestrictAnonymous=4,0", "vulnerable"),
        ("W-51", LSA + "RestrictAnonymousSAM=4,1", LSA + "RestrictAnonymousSAM=4,0", "vulnerable"),
        ("W-52", "AutoAdminLogon=0", "AutoAdminLogon=1", "vulnerable"),
        ("W-52", "AutoAdminLogon=0", "AutoAdminLogon=", "good"),
        ("W-53", 'AllocateDASD=1,"0"', 'AllocateDASD=1,"2"', "vulnerable"),
    ],
)
def test_windows_high_rule_boundaries(item: str, old: str, new: str, expected: str) -> None:
    status, reason = judged(replaced(old, new))[item]
    assert status == expected, reason


def test_screen_saver_needs_password_and_ten_minutes_without_inactivity_limit() -> None:
    text = replaced("InactivityTimeoutSecs=4,600", "InactivityTimeoutSecs=4,0")
    assert judged(text)["W-47"][0] == "good"
    status, reason = judged(text.replace("ScreenSaverIsSecure=1", "ScreenSaverIsSecure=0"))["W-47"]
    assert status == "vulnerable"
    assert "암호 미사용" in reason
    policy = text.replace("PolicyScreenSaveTimeOut=NOT_SET", "PolicyScreenSaveTimeOut=1200")
    assert judged(policy)["W-47"][0] == "vulnerable"  # 그룹 정책 값이 우선


def test_dns_zone_transfer() -> None:
    text = replaced(FTP_ON, FTP_ON + "SERVICE=DNS STATUS=Running START=Automatic\n")
    assert judged(text)["W-25"][0] == "vulnerable"  # 영역 정보 확인 불가
    zones = text.replace("DNS_ZONES=unavailable", "DNS_ZONE_TRANSFER=3\nDNS_ZONE_TRANSFER=2")
    assert judged(zones)["W-25"][0] == "good"
    assert (
        judged(zones.replace("DNS_ZONE_TRANSFER=2", "DNS_ZONE_TRANSFER=0"))["W-25"][0]
        == "vulnerable"
    )


def test_ftp_running_without_site_details_needs_manual_check() -> None:
    text = replaced(FTP_ON, FTP_ON + "SERVICE=FTPSVC STATUS=Running START=Automatic\n")
    result = judged(text)
    assert {result[c][0] for c in ("W-21", "W-22", "W-23", "W-24")} == {"vulnerable"}


def test_rds_on_old_windows_with_iis() -> None:
    text = replaced(FTP_ON, FTP_ON + "SERVICE=W3SVC STATUS=Running START=Automatic\n")
    assert judged(text)["W-26"][0] == "good"  # 2022
    old = text.replace("Standard 10.0.20348", "Standard 5.2.3790")
    assert judged(old)["W-26"][0] == "vulnerable"
    assert judged(old.replace("MSADC_VDIR=unknown", "MSADC_VDIR=False"))["W-26"][0] == "good"

"""KISA 2026 Unix 중요도 '중'·'하' 항목(스크립트 v1.3 추가분) 규칙의 경계.

강화 서버 fixture 를 한 군데씩 바꿔 판정을 확인한다.
"""

from pathlib import Path

import pytest

from modules.compliance.guideline_mapper import map_log
from modules.parser.log_parser import parse_log

HARDENED = (Path(__file__).with_name("fixtures") / "linux_hardened.txt").read_text(encoding="utf-8")


def judged(text: str) -> dict[str, tuple[str, str]]:
    mapped = map_log(parse_log(text))
    assert mapped.errors == []
    return {r.item_code: (r.status, r.reason) for r in mapped.results}


def section_replaced(item: str, old: str, new: str, text: str = HARDENED) -> str:
    begin, end = f"==== {item} BEGIN ====", f"==== {item} END ===="
    start, stop = text.index(begin), text.index(end)
    body = text[start:stop]
    assert old in body, f"{item} 구간에 '{old}' 가 없습니다"
    return text[:start] + body.replace(old, new, 1) + text[stop:]


FTP_ON = "SERVICE=vsftpd ACTIVE=active ENABLED=enabled"
FTP_OFF = "SERVICE=vsftpd ACTIVE=inactive ENABLED=not-found"
SNMP_LINE = "SNMP=rouser USER=nmsadmin\n"


@pytest.mark.parametrize(
    ("item", "old", "new", "expected"),
    [
        # 계정 관리
        ("U-07", "UID=1001 STALE=no", "UID=1001 STALE=yes", "vulnerable"),
        ("U-07", "UID=0 STALE=no", "UID=0 STALE=yes", "good"),  # root 는 대상 아님
        ("U-07", "SHELL=/sbin/nologin", "SHELL=/bin/bash", "vulnerable"),  # lp 로그인 가능
        (
            "U-07",
            "ACCOUNT=root UID=0 STALE=no\n",
            "LASTLOG=unavailable\n",
            "vulnerable",
        ),
        ("U-08", "(GID 0)\n", "(GID 0)\nUSER=opsadmin\n", "vulnerable"),
        ("U-08", "(GID 0)\n", "(GID 0)\nUSER=root\n", "good"),
        ("U-09", "member\n", "member\nGROUP=oldproj EMPTY=yes\n", "vulnerable"),
        ("U-10", "/etc/passwd\n", "/etc/passwd\nDUP_UID=1001 COUNT=2\n", "vulnerable"),
        ("U-11", "shell\n", "shell\nSYSTEM_SHELL=daemon:/bin/sh\n", "vulnerable"),
        ("U-12", "readonly TMOUT=600", "readonly TMOUT=900", "vulnerable"),
        ("U-12", "readonly TMOUT=600\n", "", "vulnerable"),
        ("U-12", "readonly TMOUT=600", "TMOUT=300", "good"),
        ("U-13", "HASH_ALGO=6 COUNT=3", "HASH_ALGO=1 COUNT=1", "vulnerable"),
        ("U-13", "HASH_ALGO=6 COUNT=3", "HASH_ALGO=y COUNT=3", "good"),
        ("U-13", "ENCRYPT_METHOD SHA512", "ENCRYPT_METHOD MD5", "vulnerable"),
        # 파일·디렉터리
        (
            "U-29",
            "MISSING=/etc/hosts.lpd",
            "FILE=/etc/hosts.lpd OWNER=root GROUP=root MODE=644",
            "vulnerable",
        ),
        (
            "U-29",
            "MISSING=/etc/hosts.lpd",
            "FILE=/etc/hosts.lpd OWNER=root GROUP=root MODE=600",
            "good",
        ),
        ("U-30", "\n0027\n", "\n0002\n", "vulnerable"),
        ("U-30", "\n0027\n", "\n0022\n", "good"),
        ("U-31", "deploy GROUP=deploy MODE=750", "deploy GROUP=deploy MODE=777", "vulnerable"),
        ("U-31", "OWNER=deploy GROUP=deploy", "OWNER=root GROUP=deploy", "vulnerable"),
        ("U-32", "missing\n", "missing\nUSER=olduser HOME_EXISTS=no\n", "vulnerable"),
        ("U-33", "/dev\n", "/dev\nHIDDEN=/dev/.rootkit\n", "vulnerable"),
        # 서비스
        ("U-48", "disable_vrfy_command = yes", "disable_vrfy_command = no", "vulnerable"),
        ("U-51", "allow-update { none; };", "allow-update { any; };", "vulnerable"),
        ("U-52", "LISTEN=tcp/0.0.0.0:22\n", "LISTEN=tcp/0.0.0.0:23\n", "vulnerable"),
        (
            "U-52",
            "SERVICE=telnet.socket ACTIVE=inactive",
            "SERVICE=telnet.socket ACTIVE=active",
            "vulnerable",
        ),
        ("U-53", FTP_OFF, FTP_ON, "vulnerable"),  # 기본 배너
        ("U-54", FTP_OFF, FTP_ON, "vulnerable"),  # TLS 미요구
        ("U-55", "FTP_ACCOUNT_SHELL=/sbin/nologin", "FTP_ACCOUNT_SHELL=/bin/bash", "vulnerable"),
        ("U-56", FTP_OFF, FTP_ON, "vulnerable"),
        ("U-57", FTP_OFF, FTP_ON, "vulnerable"),
        ("U-58", "SERVICE=snmpd ACTIVE=inactive", "SERVICE=snmpd ACTIVE=active", "vulnerable"),
        (
            "U-60",
            SNMP_LINE,
            SNMP_LINE + "SNMP=rocommunity COMMUNITY=MASKED STRENGTH=weak SOURCE=10.0.0.0/8\n",
            "vulnerable",
        ),
        (
            "U-60",
            SNMP_LINE,
            SNMP_LINE + "SNMP=rocommunity COMMUNITY=MASKED STRENGTH=ok SOURCE=10.0.0.0/8\n",
            "good",
        ),
        (
            "U-60",
            SNMP_LINE,
            SNMP_LINE + "SNMP=rocommunity COMMUNITY=public STRENGTH=weak SOURCE=none\n",
            "vulnerable",
        ),
        ("U-62", "banner /etc/issue.net", "banner none", "vulnerable"),
        ("U-63", "MODE=440", "MODE=666", "vulnerable"),
        ("U-63", "OWNER=root", "OWNER=deploy", "vulnerable"),
        # 로그
        ("U-65", "NTPSynchronized=yes", "NTPSynchronized=no", "good"),  # chronyd + 서버 설정
        (
            "U-65",
            "SERVICE=chronyd ACTIVE=active ENABLED=enabled",
            "SERVICE=chronyd ACTIVE=inactive ENABLED=disabled",
            "good",  # 동기화 완료면 양호
        ),
        (
            "U-67",
            "LOG_FILES=24\n",
            "LOG_FILES=24\nBAD FILE=/var/log/secure OWNER=root GROUP=root MODE=666\n",
            "vulnerable",
        ),
    ],
)
def test_medium_low_rule_boundaries(item: str, old: str, new: str, expected: str) -> None:
    status, reason = judged(section_replaced(item, old, new))[item]
    assert status == expected, reason


def test_u62_requires_warning_words() -> None:
    text = HARDENED
    start, stop = text.index("==== U-62 BEGIN"), text.index("==== U-62 END")
    body = "\n".join(
        line for line in text[start:stop].splitlines() if not line.startswith("BANNER_TEXT")
    )
    body += "\nBANNER_TEXT: Rocky Linux 9.4\n"
    assert judged(text[:start] + body + text[stop:])["U-62"][0] == "vulnerable"


def test_u65_no_time_service() -> None:
    text = section_replaced("U-65", "NTPSynchronized=yes", "NTPSynchronized=no")
    text = section_replaced(
        "U-65",
        "SERVICE=chronyd ACTIVE=active ENABLED=enabled",
        "SERVICE=chronyd ACTIVE=inactive ENABLED=disabled",
        text,
    )
    assert judged(text)["U-65"][0] == "vulnerable"


def test_ftp_with_tls_banner_and_access_control_is_good() -> None:
    text = HARDENED
    for item in ("U-53", "U-54", "U-56", "U-57"):
        text = section_replaced(item, FTP_OFF, FTP_ON, text)
    text = section_replaced(
        "U-53",
        "vsftpd/vsftpd.conf\n",
        "vsftpd/vsftpd.conf\nftpd_banner=Authorized use only\n",
        text,
    )
    text = section_replaced(
        "U-54",
        "vsftpd/vsftpd.conf\n",
        "vsftpd/vsftpd.conf\nssl_enable=YES\nforce_local_logins_ssl=YES\n",
        text,
    )
    text = section_replaced(
        "U-56",
        "vsftpd/vsftpd.conf\n",
        "vsftpd/vsftpd.conf\ntcp_wrappers=YES\n",
        text,
    )
    text = section_replaced(
        "U-56", "/etc/hosts.deny\n", "/etc/hosts.deny\nvsftpd: 10.0.0.0/255.0.0.0\n", text
    )
    text = section_replaced(
        "U-57", "/etc/vsftpd.user_list\n", "/etc/vsftpd.user_list\nroot\n", text
    )
    result = judged(text)
    assert {result[c][0] for c in ("U-53", "U-54", "U-56", "U-57")} == {"good"}

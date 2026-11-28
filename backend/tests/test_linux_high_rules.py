"""KISA 2026 Unix '상' 항목(스크립트 v1.2 추가분) 규칙의 경계.

양호 fixture 를 한 군데씩 바꿔 판정을 확인한다.
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


def section_replaced(item: str, old: str, new: str) -> str:
    """item 구간 안에서만 old 를 new 로 바꾼다(같은 줄이 여러 구간에 있어도 안전)."""
    begin, end = f"==== {item} BEGIN ====", f"==== {item} END ===="
    start, stop = HARDENED.index(begin), HARDENED.index(end)
    body = HARDENED[start:stop]
    assert old in body, f"{item} 구간에 '{old}' 가 없습니다"
    return HARDENED[:start] + body.replace(old, new, 1) + HARDENED[stop:]


MAIL_ON = "SERVICE=postfix ACTIVE=active ENABLED=enabled"
MAIL_OFF = "SERVICE=postfix ACTIVE=inactive ENABLED=disabled"
NFS_OFF = "SERVICE=nfs-server ACTIVE=inactive ENABLED=disabled"
NFS_ON = "SERVICE=nfs-server ACTIVE=active ENABLED=enabled"


@pytest.mark.parametrize(
    ("item", "old", "new", "expected"),
    [
        # 계정 관리
        ("U-05", "UID0=root\n", "UID0=root\nUID0=backdoor\n", "vulnerable"),
        ("U-05", "UID0=root\n", "", "vulnerable"),  # 근거 없음
        ("U-06", "auth\t\trequired\tpam_wheel.so use_uid\n", "", "good"),  # su 4750 wheel
        (
            "U-06",
            "auth\t\trequired\tpam_wheel.so use_uid\n",
            "#auth required pam_wheel.so\n",
            "good",
        ),
        ("U-06", "GROUP=wheel MODE=4750", "GROUP=root MODE=4755", "good"),  # PAM 으로 제한
        # 파일·디렉터리
        (
            "U-17",
            "STARTUP_FILES=312\n",
            "STARTUP_FILES=312\nBAD FILE=/etc/init.d/app OWNER=deploy GROUP=deploy MODE=755\n",
            "vulnerable",
        ),
        ("U-17", "STARTUP_FILES=312", "STARTUP_FILES=0", "vulnerable"),
        ("U-19", "MODE=644", "MODE=664", "vulnerable"),
        ("U-19", "OWNER=root", "OWNER=bin", "vulnerable"),  # hosts 는 root 만
        (
            "U-20",
            "MISSING=/etc/xinetd.conf",
            "FILE=/etc/xinetd.conf OWNER=root GROUP=root MODE=600",
            "good",
        ),
        (
            "U-20",
            "MISSING=/etc/xinetd.conf",
            "FILE=/etc/xinetd.conf OWNER=root GROUP=root MODE=644",
            "vulnerable",
        ),
        ("U-21", "OWNER=root GROUP=root MODE=640", "OWNER=bin GROUP=bin MODE=640", "good"),
        ("U-21", "MODE=640", "MODE=644", "vulnerable"),
        ("U-22", "OWNER=root", "OWNER=sys", "good"),
        ("U-22", "OWNER=root", "OWNER=nobody", "vulnerable"),
        (
            "U-23",
            "SPECIAL=/usr/bin/su\n",
            "SPECIAL=/usr/bin/su\nSPECIAL=/sbin/dump\n",
            "vulnerable",
        ),
        (
            "U-23",
            "SPECIAL=/usr/bin/su\n",
            "SPECIAL=/usr/bin/su\nSPECIAL=/tmp/.x/sh\n",
            "vulnerable",
        ),
        ("U-24", "deploy GROUP=deploy MODE=600", "deploy GROUP=deploy MODE=622", "vulnerable"),
        ("U-24", "OWNER=deploy GROUP=deploy", "OWNER=opsadmin GROUP=deploy", "vulnerable"),
        (
            "U-25",
            "-perm -0002\n",
            "-perm -0002\nWORLD_WRITABLE=/opt/app/run.sh\n",
            "vulnerable",
        ),
        ("U-26", "shm 제외)\n", "shm 제외)\nDEV_FILE=/dev/.hidden/rk.conf\n", "vulnerable"),
        # r 계열 미사용이면 .rhosts 가 있어도 양호(참고 사유), 사용 중이면 취약
        (
            "U-27",
            "<home>/.rhosts\n",
            "<home>/.rhosts\n"
            "USER=root FILE=/etc/hosts.equiv OWNER=root GROUP=root MODE=644 PLUS=1\n",
            "good",
        ),
        (
            "U-28",
            "SERVICE=firewalld ACTIVE=active ENABLED=enabled",
            "SERVICE=firewalld ACTIVE=inactive ENABLED=disabled",
            "good",
        ),  # nft 규칙
        ("U-28", "NFT_INPUT_RULES=14", "NFT_INPUT_RULES=0", "good"),  # firewalld
        # 서비스
        ("U-37", "MODE=750", "MODE=4755", "vulnerable"),  # crontab SUID
        (
            "U-37",
            "cron.deny OWNER=root GROUP=root MODE=600",
            "cron.deny OWNER=root GROUP=root MODE=644",
            "vulnerable",
        ),
        (
            "U-38",
            "LISTEN=tcp/0.0.0.0:22\n",
            "LISTEN=tcp/0.0.0.0:22\nLISTEN=udp/0.0.0.0:19\n",
            "vulnerable",
        ),
        (
            "U-38",
            "echo discard daytime chargen\n",
            "echo discard daytime chargen\nXINETD_ENABLED=echo-stream\n",
            "vulnerable",
        ),
        ("U-39", NFS_OFF, NFS_ON, "vulnerable"),
        ("U-39", "rpc.lockd\n", "rpc.lockd\nPROCESS=nfsd\n", "vulnerable"),
        ("U-41", "SERVICE=autofs ACTIVE=inactive", "SERVICE=autofs ACTIVE=active", "vulnerable"),
        ("U-42", "cachefsd\n$ pgrep", "cachefsd\nXINETD_ENABLED=rstatd\n$ pgrep", "vulnerable"),
        ("U-43", "SERVICE=ypbind ACTIVE=inactive", "SERVICE=ypbind ACTIVE=active", "vulnerable"),
        ("U-44", "tftp talk ntalk\n", "tftp talk ntalk\nINETD_ENABLED=talk\n", "vulnerable"),
        (
            "U-44",
            "LISTEN=tcp/0.0.0.0:443\n",
            "LISTEN=tcp/0.0.0.0:443\nLISTEN=udp/0.0.0.0:69\n",
            "vulnerable",
        ),
        ("U-45", "MAIL_PENDING_UPDATES=0", "MAIL_PENDING_UPDATES=2", "vulnerable"),
        ("U-45", "MAIL_PENDING_UPDATES=0\n", "", "vulnerable"),  # 최신 여부 확인 불가
        ("U-45", MAIL_ON, MAIL_OFF, "good"),  # master 프로세스가 남아 있으면 사용 중
        (
            "U-46",
            "postsuper OWNER=root GROUP=root MODE=750",
            "postsuper OWNER=root GROUP=root MODE=755",
            "vulnerable",
        ),
        ("U-47", "defer_unauth_destination", "permit", "vulnerable"),
        ("U-47", "mynetworks = 127.0.0.0/8", "mynetworks = 0.0.0.0/0", "vulnerable"),
        ("U-49", "DNS_PENDING_UPDATES=0", "DNS_PENDING_UPDATES=1", "vulnerable"),
        ("U-50", "allow-transfer { MASKED_IP_002; };", "allow-transfer { any; };", "vulnerable"),
        ("U-50", "\tallow-transfer { MASKED_IP_002; };\n", "", "vulnerable"),  # 미설정 = 모두 허용
        (
            "U-59",
            "SNMP=rouser USER=nmsadmin\n",
            "SNMP=rouser USER=nmsadmin\nSNMP=rocommunity COMMUNITY=MASKED SOURCE=10.0.0.0/24\n",
            "vulnerable",
        ),
        ("U-59", "SNMP=createUser USER=nmsadmin\nSNMP=rouser USER=nmsadmin\n", "", "vulnerable"),
        (
            "U-61",
            "SNMP=rouser USER=nmsadmin\n",
            "SNMP=rouser USER=nmsadmin\nSNMP=rocommunity COMMUNITY=MASKED SOURCE=10.0.0.0/24\n",
            "good",
        ),
        (
            "U-61",
            "SNMP=rouser USER=nmsadmin\n",
            "SNMP=rouser USER=nmsadmin\nSNMP=rocommunity COMMUNITY=MASKED SOURCE=none\n",
            "vulnerable",
        ),
        (
            "U-61",
            "SNMP=rouser USER=nmsadmin\n",
            "SNMP=rouser USER=nmsadmin\n"
            "SNMP=com2sec SECNAME=ro SOURCE=MASKED_IP_003 COMMUNITY=public\n",
            "vulnerable",
        ),
    ],
)
def test_high_rule_boundaries(item: str, old: str, new: str, expected: str) -> None:
    status, reason = judged(section_replaced(item, old, new))[item]
    assert status == expected, reason


def test_r_services_in_use_with_plus_entry_is_vulnerable() -> None:
    text = section_replaced(
        "U-27",
        "SERVICE=rsh.socket ACTIVE=inactive",
        "SERVICE=rsh.socket ACTIVE=active",
    )
    text = text.replace(
        "<home>/.rhosts\n",
        "<home>/.rhosts\n"
        "USER=deploy FILE=/home/deploy/.rhosts OWNER=deploy GROUP=deploy MODE=600 PLUS=1\n",
    )
    status, reason = judged(text)["U-27"]
    assert status == "vulnerable"
    assert "'+' 설정" in reason


def test_nfs_exports_access_control() -> None:
    text = section_replaced("U-40", NFS_OFF, NFS_ON)
    text = text.replace(
        "NOT_FOUND=/etc/exports\n$ stat /etc/exports\nMISSING=/etc/exports",
        '$ grep -v "^#" /etc/exports\n/data MASKED_IP_004(rw,sync)\n/pub *(ro)\n'
        "$ stat /etc/exports\nFILE=/etc/exports OWNER=root GROUP=root MODE=644",
    )
    status, reason = judged(text)["U-40"]
    assert status == "vulnerable"
    assert "/pub" in reason and "/data" not in reason
    safe = text.replace("/pub *(ro)\n", "")
    assert judged(safe)["U-40"][0] == "good"


def test_sendmail_relay_and_queue_rules() -> None:
    text = HARDENED
    for item in ("U-46", "U-47"):
        start, stop = text.index(f"==== {item} BEGIN"), text.index(f"==== {item} END")
        body = (
            text[start:stop]
            .replace(MAIL_ON, MAIL_OFF)
            .replace("PROCESS=master\n", "PROCESS=sendmail\n")
        )
        text = text[:start] + body + text[stop:]
    result = judged(text)
    assert result["U-46"][0] == "vulnerable"  # restrictqrun 없음
    assert result["U-47"][0] == "vulnerable"  # Relaying denied 규칙 없음
    fixed = text.replace(
        "sendmail.cf 2>/dev/null\n$ stat",
        "sendmail.cf 2>/dev/null\nO PrivacyOptions=authwarnings,novrfy,noexpn,restrictqrun\n$ stat",
    ).replace(
        "SENDMAIL_RELAY_RULES=/'\n",
        "SENDMAIL_RELAY_RULES=/'\nSENDMAIL_RELAY_RULES=1\n",
    )
    result = judged(fixed)
    assert (result["U-46"][0], result["U-47"][0]) == ("good", "good")

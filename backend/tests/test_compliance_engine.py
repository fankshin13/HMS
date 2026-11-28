"""규칙 기반 판정 엔진: 실제 스크립트 출력과 변형 입력으로 항목별 판정을 검증한다."""

from pathlib import Path

import pytest

from modules.compliance.guideline_mapper import RULES, map_log
from modules.parser.log_parser import parse_log

FIXTURES = Path(__file__).with_name("fixtures")


def read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def statuses(text: str) -> dict[str, str]:
    return {r.item_code: r.status for r in map_log(parse_log(text)).results}


# --- 파서 -------------------------------------------------------------------------------


def test_parser_reads_header_info_and_sections() -> None:
    log = parse_log(read("linux_hardened.txt"))
    assert (log.os_type, log.hostname, log.has_end) == ("linux", "web-01", True)
    assert log.info["DISTRO"] == ["Rocky Linux 9.4 (Blue Onyx)"]
    assert set(log.sections) == {r.section for r in RULES["linux"]}
    assert log.error_lines == []
    u01 = log.sections["U-01"]
    assert u01.command_output("permitrootlogin") == ["permitrootlogin no"]
    assert (u01.start_line, u01.end_line) < (u01.end_line + 1, u01.end_line + 1)


def test_parser_handles_crlf_windows_output() -> None:
    log = parse_log(read("windows_default.txt"))
    assert (log.os_type, log.hostname, log.error_lines) == ("windows", "WIN-SRV-01", [])


def test_parser_never_raises_and_reports_line_numbers() -> None:
    text = read("linux_hardened.txt")
    broken = text.replace("==== U-08 END ====", "").replace(
        "[INFO] IP=", "GARBAGE LINE\n[INFO] IP="
    )
    log = parse_log(broken + "\x00\x01binary")
    reasons = [e.reason for e in log.error_lines]
    assert "표준 형식이 아닌 줄입니다" in reasons
    assert any("U-08" in r for r in reasons)
    garbage = next(e for e in log.error_lines if e.raw_snippet == "GARBAGE LINE")
    assert garbage.line_number == 4


@pytest.mark.parametrize("text", ["", "random", "\x00\x00", "==== X END ====\n[END]"])
def test_parser_survives_garbage(text: str) -> None:
    log = parse_log(text)
    assert log.hostname is None
    assert log.error_lines


# --- 실제 Ubuntu 기본 설치 출력 ----------------------------------------------------------------

UBUNTU_EXPECTED = {
    "U-01": "good",  # SSH·Telnet 미사용
    "U-02": "vulnerable",  # pwquality 미설정
    "U-03": "vulnerable",  # 잠금 임계값 없음
    "U-04": "good",
    "U-05": "good",
    "U-06": "vulnerable",  # 소유자 없는 파일 존재
    "U-07": "good",
    "U-08": "vulnerable",  # /etc/shadow 640
    "U-19": "good",
    "U-20": "na",  # FTP 미사용
    "U-21": "good",
    "U-42": "vulnerable",  # 보안 업데이트 33건 대기
    "U-43": "vulnerable",  # 인터뷰 필요(보수적 판정)
    "U-72": "vulnerable",  # rsyslog 미실행
}


def test_real_ubuntu_output_is_judged_item_by_item() -> None:
    mapped = map_log(parse_log(read("linux_ubuntu_default.txt")))
    assert mapped.errors == []
    assert {r.item_code: r.status for r in mapped.results} == UBUNTU_EXPECTED
    u08 = next(r for r in mapped.results if r.item_code == "U-08")
    assert u08.stdout_snippet.startswith("[판정 근거] /etc/shadow 소유자 root, 권한 640")
    assert "OWNER=root MODE=640" in u08.stdout_snippet


def test_hardened_linux_is_all_good_except_interview_and_na() -> None:
    result = statuses(read("linux_hardened.txt"))
    assert result.pop("U-43") == "vulnerable"
    assert result.pop("U-20") == "good"  # 설정 파일 존재·익명 차단
    assert set(result.values()) == {"good"}


# --- 개별 규칙의 경계 -----------------------------------------------------------------------

HARDENED = "linux_hardened.txt"


@pytest.mark.parametrize(
    ("item", "old", "new", "expected"),
    [
        ("U-01", "permitrootlogin no", "permitrootlogin yes", "vulnerable"),
        ("U-01", "permitrootlogin no", "permitrootlogin prohibit-password", "vulnerable"),
        ("U-02", "ocredit = -1\n", "", "good"),  # 3종 8자
        ("U-02", "ucredit = -1\nlcredit = -1\nocredit = -1\n", "", "vulnerable"),  # 1종 8자
        ("U-02", "minlen = 8\nd", "minlen = 10\nd", "good"),
        ("U-03", "deny = 5", "deny = 10", "good"),
        ("U-03", "deny = 5", "deny = 11", "vulnerable"),
        ("U-03", "deny = 5", "deny = 0", "vulnerable"),
        ("U-04", "NON_SHADOW_COUNT=0", "NON_SHADOW_COUNT=2", "vulnerable"),
        ("U-05", "PATH=/usr/local/sbin:", "PATH=.:/usr/local/sbin:", "vulnerable"),
        ("U-05", "/usr/bin:/root/bin", "/usr/bin::/root/bin", "vulnerable"),
        ("U-05", "/usr/bin:/root/bin", "/usr/bin:/root/bin:.", "good"),  # 맨 뒤는 허용
        ("U-07", "MODE=644 FILE=/etc/passwd", "MODE=664 FILE=/etc/passwd", "vulnerable"),
        ("U-07", "MODE=644 FILE=/etc/passwd", "MODE=600 FILE=/etc/passwd", "good"),
        ("U-08", "MODE=0 FILE=/etc/shadow", "MODE=400 FILE=/etc/shadow", "good"),
        (
            "U-08",
            "OWNER=root MODE=0 FILE=/etc/shadow",
            "OWNER=bin MODE=0 FILE=/etc/shadow",
            "vulnerable",
        ),
        ("U-20", "anonymous_enable=NO", "anonymous_enable=YES", "vulnerable"),
        ("U-42", "RESULT=OK\n", "", "vulnerable"),  # rpm 계열은 근거 부족 → 보수적
        ("U-42", "RESULT=OK", "RESULT=N/A", "na"),
        ("U-72", "authpriv.*", "#authpriv.*", "vulnerable"),
    ],
)
def test_rule_boundaries(item: str, old: str, new: str, expected: str) -> None:
    text = read(HARDENED)
    assert old in text, f"fixture 에 '{old}' 가 없습니다"
    assert statuses(text.replace(old, new, 1))[item] == expected


def test_services_detected_as_vulnerable() -> None:
    text = read(HARDENED)
    text = text.replace(
        "$ ss -ltn 2>/dev/null | grep -E ':79\\b'\n",
        "$ ss -ltn 2>/dev/null | grep -E ':79\\b'\nLISTEN 0 64 0.0.0.0:79 0.0.0.0:*\n",
    )
    text = text.replace(
        "grep -Ei 'rsh|rlogin|rexec'\n",
        "grep -Ei 'rsh|rlogin|rexec'\nrsh.socket                    enabled         disabled\n",
    )
    result = statuses(text)
    assert (result["U-19"], result["U-21"]) == ("vulnerable", "vulnerable")


# --- Windows -----------------------------------------------------------------------------


def test_windows_default_output() -> None:
    assert statuses(read("windows_default.txt")) == {
        "W-01": "vulnerable",  # Administrator 이름 그대로
        "W-02": "good",  # Guest 비활성
        "W-04": "vulnerable",  # 잠금 임계값 없음
        "W-05": "good",  # 해독 가능한 암호화 사용 안 함
    }


@pytest.mark.parametrize(
    ("item", "old", "new", "expected"),
    [
        (
            "W-01",
            "ACCOUNT=Administrator ENABLED=True RID=500",
            "ACCOUNT=MASKED_USER_009 ENABLED=True RID=500",
            "good",
        ),
        ("W-02", "ACCOUNT=Guest ENABLED=False", "ACCOUNT=Guest ENABLED=True", "vulnerable"),
        ("W-04", "LockoutBadCount = 0", "LockoutBadCount = 5", "good"),
        ("W-04", "LockoutBadCount = 0", "LockoutBadCount = 6", "vulnerable"),
        ("W-05", "ClearTextPassword = 0", "ClearTextPassword = 1", "vulnerable"),
    ],
)
def test_windows_rule_boundaries(item: str, old: str, new: str, expected: str) -> None:
    assert statuses(read("windows_default.txt").replace(old, new, 1))[item] == expected


# --- 결함 격리 -----------------------------------------------------------------------------


def test_damaged_log_keeps_healthy_items_and_reports_errors() -> None:
    text = (
        read(HARDENED)
        .replace("==== U-08 END ====\n", "")
        .replace("==== U-19 BEGIN ====", "@@corrupted@@\n==== U-19 BEGIN ====")
    )
    mapped = map_log(parse_log(text))
    judged = {r.item_code for r in mapped.results}
    assert "U-01" in judged and "U-72" in judged
    assert mapped.quarantined
    assert any("U-08" in e.reason for e in mapped.errors)


def test_missing_section_is_reported_not_guessed() -> None:
    text = read(HARDENED)
    start = text.index("==== U-21 BEGIN ====")
    end = text.index("==== U-21 END ====") + len("==== U-21 END ====")
    mapped = map_log(parse_log(text[:start] + text[end:]))
    assert "U-21" not in {r.item_code for r in mapped.results}
    assert any("U-21" in e.reason for e in mapped.errors)


def test_every_rule_code_is_seeded_in_compliance_guidelines() -> None:
    migrations = "".join(
        p.read_text() for p in (Path(__file__).parents[2] / "supabase" / "migrations").glob("*.sql")
    )
    for rules in RULES.values():
        for rule in rules:
            assert f"('{rule.item_code}'," in migrations, rule.item_code


def test_proftpd_anonymous_block_is_vulnerable() -> None:
    text = read(HARDENED).replace(
        "/etc/proftpd.conf 2>/dev/null\n", "/etc/proftpd.conf 2>/dev/null\n<Anonymous ~ftp>\n", 1
    )
    assert statuses(text)["U-20"] == "vulnerable"

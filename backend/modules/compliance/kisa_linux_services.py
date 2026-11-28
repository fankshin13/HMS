"""KISA 2026 Unix 서비스 관리 '상' 항목 판정 규칙 (kisa_check_linux.sh v1.2 이상).

서비스를 쓰지 않으면 '해당없음', 쓰는데 설정을 자동으로 확인할 수 없으면
보수적으로 '취약'으로 판정한다.
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
from modules.parser.log_parser import ParsedLog, Section

V12 = (1, 2, 0)


def _running(section: Section) -> list[str]:
    return active_services(section) + inet_enabled(section)


def _first_int(section: Section, key: str) -> int | None:
    return int_or_none(next(iter(section.values(key)), None))


def u37(section: Section, _: ParsedLog) -> Judgement:
    stats = file_stats(section.lines)
    commands = [s for s in stats if s.fields.get("KIND") == "cmd"]
    configs = [s for s in stats if s.fields.get("KIND") == "conf"]
    if section.command_output("crontab/at commands") is None:
        return vulnerable("cron·at 파일 정보를 확인하지 못했습니다(수동 확인 필요)")
    problems = [
        f"{s.path}(명령, {s.owner}, {s.mode_text})"
        for s in commands
        if s.owner != "root" or exceeds(s.mode, 0o750)
    ] + [
        f"{s.path}({s.owner}, {s.mode_text})"
        for s in configs
        if s.owner != "root" or exceeds(s.mode, 0o640)
    ]
    if problems:
        shown = ", ".join(problems[:6]) + (
            f" 외 {len(problems) - 6}개" if len(problems) > 6 else ""
        )
        return vulnerable(
            f"기준(명령 root·750 이하·SUID 제거, 설정 root·640 이하)을 벗어남: {shown}"
        )
    return good(f"crontab·at 명령 {len(commands)}개와 관련 파일 {len(configs)}개 권한이 적절합니다")


DOS_PORTS = {7, 9, 13, 19}


def u38(section: Section, _: ParsedLog) -> Judgement:
    if section.command_output("echo discard daytime chargen") is None:
        return vulnerable("DoS 취약 서비스 상태를 확인하지 못했습니다(수동 확인 필요)")
    found = inet_enabled(section) + [
        f"포트 {p}" for p in sorted(listening_ports(section) & DOS_PORTS)
    ]
    if found:
        return vulnerable(f"DoS 공격에 취약한 서비스가 활성화되어 있습니다: {', '.join(found)}")
    return good("echo·discard·daytime·chargen 서비스가 비활성화되어 있습니다")


def u39(section: Section, _: ParsedLog) -> Judgement:
    running = _running(section)
    if running:
        return vulnerable(
            f"NFS 서비스가 활성화되어 있습니다({', '.join(running)}). "
            "업무상 필요하면 사유와 함께 판정을 변경하세요"
        )
    return good("NFS 서비스 관련 데몬이 비활성화되어 있습니다")


def u40(section: Section, _: ParsedLog) -> Judgement:
    exports = [
        line for line in section.command_output('grep -v "^#" /etc/exports') or [] if line.strip()
    ]
    running = _running(section)
    if not running and not exports:
        return na("NFS 서비스를 사용하지 않습니다")
    problems: list[str] = []
    for line in exports:
        parts = line.split()
        clients = parts[1:]
        if not clients:
            problems.append(f"{parts[0]}(접근 호스트 미지정)")
        elif any(client.startswith("*") for client in clients):
            problems.append(f"{parts[0]}(모든 호스트 허용 '*')")
    for stat in file_stats(section.lines):
        if stat.owner != "root" or exceeds(stat.mode, 0o644):
            problems.append(f"{stat.path}(소유자 {stat.owner}, 권한 {stat.mode_text})")
    if running and not exports:
        problems.append("/etc/exports 에 접근 통제 설정 없음")
    if problems:
        return vulnerable("NFS 접근 통제 미흡: " + ", ".join(problems))
    return good("NFS 공유마다 허용 호스트가 지정되어 있고 설정 파일 권한이 644 이하입니다")


def u41(section: Section, _: ParsedLog) -> Judgement:
    running = _running(section)
    if running:
        return vulnerable(f"automountd(autofs) 서비스가 활성화되어 있습니다({', '.join(running)})")
    return good("automountd(autofs) 서비스가 비활성화되어 있습니다")


def u42(section: Section, _: ParsedLog) -> Judgement:
    running = _running(section)
    if running:
        return vulnerable(f"불필요한 RPC 서비스가 활성화되어 있습니다: {', '.join(running)}")
    return good("불필요한 RPC 서비스가 비활성화되어 있습니다")


def u43(section: Section, _: ParsedLog) -> Judgement:
    running = _running(section)
    if running:
        return vulnerable(f"NIS 서비스가 활성화되어 있습니다: {', '.join(running)}")
    return good("NIS 서비스가 비활성화되어 있습니다")


TFTP_TALK_PORTS = {69, 517, 518}


def u44(section: Section, _: ParsedLog) -> Judgement:
    found = _running(section) + [
        f"포트 {p}" for p in sorted(listening_ports(section) & TFTP_TALK_PORTS)
    ]
    if found:
        return vulnerable(f"tftp·talk 서비스가 활성화되어 있습니다: {', '.join(found)}")
    return good("tftp·talk·ntalk 서비스가 비활성화되어 있습니다")


def _versioned_service(
    section: Section, label: str, pending_key: str, version_hints: tuple[str, ...]
) -> Judgement:
    running = _running(section)
    if not running:
        return na(f"{label} 서비스를 사용하지 않습니다")
    version = next(
        (
            line.strip()
            for hint in version_hints
            for line in section.command_output(hint) or []
            if line.strip()
        ),
        "버전 확인 불가",
    )
    pending = _first_int(section, pending_key)
    if pending is None:
        return vulnerable(
            f"{label} 서비스 사용 중({version}). 최신 버전 여부를 자동으로 확인할 수 없습니다"
            "(패치 관리 수동 확인 필요)"
        )
    if pending > 0:
        return vulnerable(
            f"{label} 서비스({version})에 적용되지 않은 업데이트가 {pending}건 있습니다"
        )
    return good(f"{label} 서비스({version})가 배포판 최신 버전입니다")


def u45(section: Section, _: ParsedLog) -> Judgement:
    return _versioned_service(
        section, "메일", "MAIL_PENDING_UPDATES", ("mail_version", "exim -bV", "rpm -q")
    )


def _mail_agents(section: Section) -> set[str]:
    running = " ".join(_running(section))
    agents: set[str] = set()
    if "postfix" in running or "master" in running:
        agents.add("postfix")
    if "sendmail" in running:
        agents.add("sendmail")
    if "exim" in running:
        agents.add("exim")
    return agents


def u46(section: Section, _: ParsedLog) -> Judgement:
    agents = _mail_agents(section)
    if not agents:
        return na("메일 서비스를 사용하지 않습니다")
    stats = {s.path.rsplit("/", 1)[-1]: s for s in file_stats(section.lines)}
    problems: list[str] = []
    if "sendmail" in agents:
        options = " ".join(section.command_output("PrivacyOptions") or [])
        if "restrictqrun" not in options:
            problems.append("sendmail PrivacyOptions 에 restrictqrun 없음")
    for agent, binary in (("postfix", "postsuper"), ("exim", "exiqgrep")):
        if agent in agents:
            stat = stats.get(binary)
            if stat is None:
                problems.append(f"{binary} 권한 확인 불가")
            elif stat.mode & 0o001:
                problems.append(f"{binary} 에 일반 사용자 실행 권한({stat.mode_text})")
    if problems:
        return vulnerable(
            "일반 사용자의 메일 큐 제어가 제한되지 않았습니다: " + ", ".join(problems)
        )
    return good("일반 사용자의 메일 서비스 실행(q 옵션·큐 관리)이 제한되어 있습니다")


def u47(section: Section, _: ParsedLog) -> Judgement:
    agents = _mail_agents(section)
    if not agents:
        return na("메일 서비스를 사용하지 않습니다")
    problems: list[str] = []
    if "postfix" in agents:
        postconf = dict(
            (key.strip(), value.strip())
            for line in section.command_output("postconf smtpd_relay") or []
            if "=" in line
            for key, value in [line.split("=", 1)]
        )
        restrictions = " ".join(
            postconf.get(k, "")
            for k in ("smtpd_relay_restrictions", "smtpd_recipient_restrictions")
        )
        if not postconf:
            problems.append("postfix 릴레이 설정 확인 불가")
        elif not re.search(r"(reject|defer)_unauth_destination", restrictions):
            problems.append("postfix 에 reject_unauth_destination 없음")
        if re.search(r"(^|[\s,])0\.0\.0\.0/0", postconf.get("mynetworks", "")):
            problems.append("postfix mynetworks 가 모든 주소(0.0.0.0/0)")
    if "sendmail" in agents:
        if section.command_output("promiscuous_relay") or []:
            problems.append("sendmail promiscuous_relay 설정")
        elif not _first_int(section, "SENDMAIL_RELAY_RULES"):
            problems.append("sendmail 릴레이 제한 규칙(Relaying denied) 없음")
    if "exim" in agents:
        relay = " ".join(section.command_output("relay_from_hosts") or [])
        if re.search(r"relay_from_hosts\s*=\s*[^#\n]*(\*|0\.0\.0\.0/0)", relay):
            problems.append("exim relay_from_hosts 가 모든 호스트 허용")
    if problems:
        return vulnerable("스팸 메일 릴레이 제한 미흡: " + ", ".join(problems))
    return good("메일 서버의 릴레이가 허용된 네트워크로 제한되어 있습니다")


def u49(section: Section, _: ParsedLog) -> Judgement:
    return _versioned_service(section, "DNS(BIND)", "DNS_PENDING_UPDATES", ("named -v",))


def u50(section: Section, _: ParsedLog) -> Judgement:
    if not _running(section):
        return na("DNS 서비스를 사용하지 않습니다")
    lines = [
        line
        for line in section.command_output("allow-transfer") or []
        if line.strip() and not line.strip().startswith(("#", "//"))
    ]
    if not lines:
        return vulnerable("allow-transfer 설정이 없어 모든 호스트에 Zone Transfer 가 허용됩니다")
    if any(re.search(r"allow-transfer\s*\{\s*any\s*;", line) for line in lines):
        return vulnerable("allow-transfer { any; } 로 모든 호스트에 Zone Transfer 가 허용됩니다")
    return good("Zone Transfer 가 허가된 호스트로 제한되어 있습니다")


def _snmp_entries(section: Section) -> list[dict[str, str]]:
    return [kv(line) for line in section.lines if line.startswith("SNMP=")]


def u59(section: Section, _: ParsedLog) -> Judgement:
    if not _running(section):
        return na("SNMP 서비스를 사용하지 않습니다")
    entries = _snmp_entries(section)
    legacy = [e for e in entries if re.match(r"^(r[ow]community|com2sec)", e["SNMP"])]
    v3 = [e for e in entries if e["SNMP"] in ("createUser", "rouser", "rwuser")]
    if legacy:
        return vulnerable(
            f"SNMP v1/v2c 커뮤니티 설정이 {len(legacy)}개 있습니다(v3 사용자 인증으로 전환 필요)"
        )
    if v3:
        return good("SNMP 를 v3 사용자 인증으로만 사용합니다")
    return vulnerable("SNMP 버전 설정을 확인하지 못했습니다(수동 확인 필요)")


def u61(section: Section, _: ParsedLog) -> Judgement:
    if not _running(section):
        return na("SNMP 서비스를 사용하지 않습니다")
    entries = _snmp_entries(section)
    if not entries:
        return vulnerable("SNMP 접근 제어 설정을 확인하지 못했습니다(수동 확인 필요)")
    open_entries = [
        e
        for e in entries
        if re.match(r"^(r[ow]community|com2sec)", e["SNMP"])
        and e.get("SOURCE", "none") in ("none", "default", "0.0.0.0/0", "::/0")
    ]
    defaults = [e for e in entries if e.get("COMMUNITY") in ("public", "private")]
    if open_entries:
        return vulnerable(
            f"접근 허용 호스트를 제한하지 않은 SNMP 커뮤니티 설정이 {len(open_entries)}개 있습니다"
        )
    if defaults:
        return vulnerable("기본 커뮤니티 이름(public·private)을 사용합니다")
    return good("SNMP 접근이 허용된 호스트 또는 v3 사용자로 제한되어 있습니다")


SERVICE_RULES: list[Rule] = [
    Rule("U-37", "U-37", u37, V12),
    Rule("U-38", "U-38", u38, V12),
    Rule("U-39", "U-39", u39, V12),
    Rule("U-40", "U-40", u40, V12),
    Rule("U-41", "U-41", u41, V12),
    Rule("U-42", "U-42", u42, V12),
    Rule("U-43", "U-43", u43, V12),
    Rule("U-44", "U-44", u44, V12),
    Rule("U-45", "U-45", u45, V12),
    Rule("U-46", "U-46", u46, V12),
    Rule("U-47", "U-47", u47, V12),
    Rule("U-49", "U-49", u49, V12),
    Rule("U-50", "U-50", u50, V12),
    Rule("U-59", "U-59", u59, V12),
    Rule("U-61", "U-61", u61, V12),
]

#!/usr/bin/env bash
# =============================================================================
# 시스템 취약점 진단 - Linux 표준 점검 스크립트
#   대상: CentOS / RHEL / Rocky / Ubuntu / Debian
#   기준: KISA 2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (Unix 서버)
#
# 이 스크립트는 읽기 전용입니다. 설정을 바꾸지 않고 판정에 필요한 근거만 모아
# 현재 디렉터리에 <호스트명>_linux_<일시>.txt 파일로 저장합니다.
# 비밀번호 해시 등 비밀 값은 수집하지 않습니다.
#
# 실행: sudo bash kisa_check_linux.sh
# =============================================================================
set -u
export LC_ALL=C

SCRIPT_VERSION="1.2.0"
HOST="$(hostname 2>/dev/null || uname -n)"
STAMP="$(date +%Y%m%d%H%M%S)"
OUT="${HOST}_linux_${STAMP}.txt"
MAX_LINES=200

if [ "$(id -u)" -ne 0 ]; then
  echo "root 권한이 필요합니다: sudo bash $0" >&2
  exit 1
fi

# 명령과 출력(최대 MAX_LINES 줄)을 함께 남긴다.
run() {
  printf '$ %s\n' "$1"
  bash -c "$1" 2>&1 | head -n "$MAX_LINES"
}

# 설정 파일에서 주석·빈 줄을 뺀 내용을 남긴다.
show_conf() {
  local file="$1"
  if [ -f "$file" ]; then
    printf '$ grep -v "^#" %s\n' "$file"
    grep -Ev '^[[:space:]]*(#|$)' "$file" 2>/dev/null | head -n "$MAX_LINES"
  else
    printf 'NOT_FOUND=%s\n' "$file"
  fi
}

begin() { printf '==== %s BEGIN ====\n' "$1"; }
end() { printf '==== %s END ====\n\n' "$1"; }

# 직접 실행하는 점검 코드 앞에 명령 설명 줄을 남긴다.
hdr() { printf '$ %s\n' "$1"; }

# 파일 소유자·권한 (KEY=값). 없는 파일은 MISSING= 으로 남긴다.
stat_line() {
  hdr "stat $*"
  local file
  for file in "$@"; do
    if [ -e "$file" ]; then
      stat -c 'FILE=%n OWNER=%U GROUP=%G MODE=%a' "$file"
    else
      printf 'MISSING=%s\n' "$file"
    fi
  done
}

# systemd 서비스 상태 (SERVICE=이름 ACTIVE=상태 ENABLED=상태)
svc() {
  hdr "systemctl is-active/is-enabled $*"
  local unit active enabled
  for unit in "$@"; do
    active="$(systemctl is-active "$unit" 2>/dev/null | head -n 1)"
    enabled="$(systemctl is-enabled "$unit" 2>/dev/null | head -n 1)"
    printf 'SERVICE=%s ACTIVE=%s ENABLED=%s\n' "$unit" "${active:-unknown}" "${enabled:-not-found}"
  done
}

# 실행 중인 프로세스 (PROCESS=이름)
procs() {
  hdr "pgrep -x $*"
  local name
  for name in "$@"; do
    pgrep -x "$name" >/dev/null 2>&1 && printf 'PROCESS=%s\n' "$name"
  done
  return 0
}

# inetd·xinetd 로 켜져 있는 서비스 (INETD_ENABLED=, XINETD_ENABLED=)
inet_check() {
  hdr "inetd/xinetd $*"
  local name file
  for name in "$@"; do
    if [ -f /etc/inetd.conf ] && grep -Eq "^[[:space:]]*${name}[[:space:]]" /etc/inetd.conf; then
      printf 'INETD_ENABLED=%s\n' "$name"
    fi
    for file in /etc/xinetd.d/"$name"*; do
      if [ -f "$file" ] && ! grep -Eqi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$file"; then
        printf 'XINETD_ENABLED=%s\n' "$(basename "$file")"
      fi
    done
  done
  return 0
}

# 수신 대기 포트 (LISTEN=프로토콜/주소:포트)
listen() {
  hdr "ss -ltnu"
  ss -ltnu 2>/dev/null | awk 'NR > 1 {print "LISTEN=" $1 "/" $5}'
}

# SNMP 설정 요약. 커뮤니티 문자열·v3 비밀번호는 남기지 않는다(public/private 기본값 여부만 표시).
snmp_conf() {
  hdr "snmpd.conf (community/user lines, secrets masked)"
  grep -Ehs '^[[:space:]]*(rocommunity6?|rwcommunity6?|com2sec6?|createUser|rouser|rwuser)[[:space:]]' \
    /etc/snmp/snmpd.conf /var/lib/net-snmp/snmpd.conf /var/lib/snmp/snmpd.conf 2>/dev/null |
    awk 'function c(v) { return (v == "public" || v == "private") ? v : "MASKED" }
      $1 ~ /^r[ow]community6?$/ { print "SNMP=" $1, "COMMUNITY=" c($2), "SOURCE=" ($3 == "" ? "none" : $3); next }
      $1 ~ /^com2sec6?$/ { print "SNMP=" $1, "SECNAME=" $2, "SOURCE=" $3, "COMMUNITY=" c($4); next }
      { print "SNMP=" $1, "USER=" $2 }'
}

# root(UID 0)와 일반 사용자(UID 1000 이상) 계정의 이름과 홈 디렉터리
user_homes() {
  awk -F: '($3 == 0 || $3 >= 1000) && $3 < 65534 {print $1, $6}' /etc/passwd
}

# 업데이트 대기 중인 패키지 수. 인자: 키 이름, 패키지 이름 정규식
# apt 는 로컬 목록, dnf·yum 은 캐시(--cacheonly)만 사용하므로 네트워크에 접속하지 않는다.
pending_updates() {
  local updates
  if command -v apt >/dev/null 2>&1; then
    hdr "apt list --upgradable (pattern: $2)"
    printf '%s=%s\n' "$1" "$(apt list --upgradable 2>/dev/null | grep -cE "^($2)/")"
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    hdr "dnf/yum check-update --cacheonly (pattern: $2)"
    if command -v dnf >/dev/null 2>&1; then
      updates="$(dnf -q --cacheonly check-update 2>/dev/null)"
    else
      updates="$(yum -q -C check-update 2>/dev/null)"
    fi
    printf '%s=%s\n' "$1" "$(printf '%s\n' "$updates" | grep -cE "^($2)\.")"
  fi
}

collect() {
  printf '[START] OS=Linux HOSTNAME=%s DATE=%s SCRIPT=kisa_check_linux VERSION=%s\n' \
    "$HOST" "$(date +%Y-%m-%dT%H:%M:%S%z)" "$SCRIPT_VERSION"
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091 # 실행 대상 서버의 파일
    printf '[INFO] DISTRO=%s\n' "$(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
  fi
  printf '[INFO] KERNEL=%s\n' "$(uname -srm)"
  ip -o -4 addr show 2>/dev/null | awk '{print "[INFO] IP=" $4}'
  echo

  begin "U-01" # root 계정 원격접속 제한
  run "sshd -T 2>/dev/null | grep -Ei '^permitrootlogin'"
  show_conf /etc/ssh/sshd_config
  run "systemctl is-active telnet.socket 2>/dev/null; systemctl is-enabled telnet.socket 2>/dev/null"
  run "grep -E '^pts' /etc/securetty 2>/dev/null"
  end "U-01"

  begin "U-02" # 비밀번호 관리정책 설정
  show_conf /etc/security/pwquality.conf
  run "grep -Eh 'pam_pwquality|pam_cracklib' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password 2>/dev/null"
  run "grep -E '^PASS_(MIN_LEN|MAX_DAYS|MIN_DAYS)' /etc/login.defs"
  show_conf /etc/security/pwhistory.conf
  run "grep -Eh 'pam_pwhistory|remember=' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password 2>/dev/null"
  end "U-02"

  begin "U-03" # 계정 잠금 임계값 설정
  show_conf /etc/security/faillock.conf
  run "grep -Eh 'pam_faillock|pam_tally2' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth 2>/dev/null"
  end "U-03"

  begin "U-04" # 패스워드 파일 보호
  # 두 번째 필드가 x 가 아닌 계정 이름만 남긴다(해시 값은 남기지 않음)
  run "awk -F: '\$2 != \"x\" {print \"ACCOUNT=\" \$1}' /etc/passwd"
  run "awk -F: '\$2 != \"x\"' /etc/passwd | wc -l | sed 's/^/NON_SHADOW_COUNT=/'"
  run "ls -l /etc/shadow"
  end "U-04"

  begin "U-05" # root 이외의 UID가 '0' 금지
  run "awk -F: '\$3 == 0 {print \"UID0=\" \$1}' /etc/passwd"
  end "U-05"

  begin "U-06" # 사용자 계정 su 기능 제한
  show_conf /etc/pam.d/su
  stat_line /usr/bin/su
  # 그룹 구성원 이름은 남기지 않고 수만 남긴다
  run "awk -F: '\$1 == \"wheel\" {print \"WHEEL_MEMBERS=\" (\$4 == \"\" ? 0 : split(\$4, m, \",\"))}' /etc/group"
  run "awk -F: '\$3 >= 1000 && \$3 < 65534 && \$7 !~ /(nologin|false)\$/ {n++} END {print \"NORMAL_USERS=\" n+0}' /etc/passwd"
  end "U-06"

  begin "U-14" # root 홈, 패스 디렉터리 권한 및 패스 설정
  # sudo 의 secure_path 가 아니라 root 로그인 셸의 PATH 를 확인한다
  run "bash -lc 'echo PATH=\$PATH'"
  run "ls -ld /root"
  end "U-14"

  begin "U-15" # 파일 및 디렉터리 소유자 설정
  run "find / -xdev \\( -nouser -o -nogroup \\) -print 2>/dev/null | head -n 50"
  end "U-15"

  begin "U-16" # /etc/passwd 파일 소유자 및 권한 설정
  run "stat -c 'OWNER=%U MODE=%a FILE=%n' /etc/passwd"
  end "U-16"

  begin "U-17" # 시스템 시작 스크립트 권한 설정
  hdr "find startup scripts (owner not root or writable by others)"
  find /etc/init.d /etc/rc.d/init.d /etc/systemd/system /usr/lib/systemd/system -xdev -type f 2>/dev/null |
    wc -l | sed 's/^/STARTUP_FILES=/'
  find /etc/init.d /etc/rc.d/init.d /etc/systemd/system /usr/lib/systemd/system -xdev -type f \
    \( ! -user root -o -perm -0002 -o \( -perm -0020 ! -group root \) \) \
    -exec stat -c 'BAD FILE=%n OWNER=%U GROUP=%G MODE=%a' {} + 2>/dev/null | head -n 50
  end "U-17"

  begin "U-18" # /etc/shadow 파일 소유자 및 권한 설정
  run "stat -c 'OWNER=%U MODE=%a FILE=%n' /etc/shadow"
  end "U-18"

  begin "U-19" # /etc/hosts 파일 소유자 및 권한 설정
  stat_line /etc/hosts
  end "U-19"

  begin "U-20" # /etc/(x)inetd.conf 파일 소유자 및 권한 설정
  stat_line /etc/inetd.conf /etc/xinetd.conf
  end "U-20"

  begin "U-21" # /etc/(r)syslog.conf 파일 소유자 및 권한 설정
  stat_line /etc/rsyslog.conf /etc/syslog.conf
  end "U-21"

  begin "U-22" # /etc/services 파일 소유자 및 권한 설정
  stat_line /etc/services
  end "U-22"

  begin "U-23" # SUID, SGID, Sticky bit 설정 파일 점검
  hdr "find / -xdev -user root -type f -perm -4000 -o -perm -2000"
  find / -xdev -user root -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -n 200 | sed 's/^/SPECIAL=/'
  end "U-23"

  begin "U-24" # 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
  hdr "stat <home>/.profile .bashrc ... (root and UID>=1000)"
  user_homes | while read -r account home; do
    for name in .profile .bashrc .bash_profile .bash_login .bash_logout .cshrc .kshrc .login .exrc .netrc; do
      [ -f "$home/$name" ] && stat -c "USER=$account FILE=%n OWNER=%U GROUP=%G MODE=%a" "$home/$name"
    done
  done
  end "U-24"

  begin "U-25" # world writable 파일 점검
  hdr "find / -xdev -type f -perm -0002"
  find / -xdev -type f -perm -0002 2>/dev/null | head -n 50 | sed 's/^/WORLD_WRITABLE=/'
  end "U-25"

  begin "U-26" # /dev에 존재하지 않는 device 파일 점검
  hdr "find /dev -type f (mqueue, shm 제외)"
  find /dev -type f ! -path '/dev/shm/*' ! -path '/dev/mqueue/*' 2>/dev/null | head -n 50 | sed 's/^/DEV_FILE=/'
  end "U-26"

  begin "U-27" # $HOME/.rhosts, hosts.equiv 사용 금지
  svc rsh.socket rlogin.socket rexec.socket
  inet_check rsh rlogin rexec shell login exec
  hdr "stat /etc/hosts.equiv <home>/.rhosts"
  { echo "root /etc/hosts.equiv"; user_homes | awk '{print $1, $2 "/.rhosts"}'; } | while read -r account file; do
    if [ -f "$file" ]; then
      printf '%s PLUS=%s\n' "$(stat -c "USER=$account FILE=%n OWNER=%U GROUP=%G MODE=%a" "$file")" \
        "$(grep -c '^[[:space:]]*+' "$file" 2>/dev/null)"
    fi
  done
  end "U-27"

  begin "U-28" # 접속 IP 및 포트 제한
  show_conf /etc/hosts.deny
  show_conf /etc/hosts.allow
  run "ufw status 2>/dev/null | head -n 30"
  svc firewalld
  hdr "iptables -S INPUT"
  printf 'IPTABLES_INPUT_RULES=%s\n' "$(iptables -S INPUT 2>/dev/null | grep -c '^-A INPUT')"
  printf 'IPTABLES_INPUT_POLICY=%s\n' "$(iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/ {print $3}')"
  hdr "nft list ruleset (input hook rules)"
  printf 'NFT_INPUT_RULES=%s\n' "$(nft list ruleset 2>/dev/null |
    awk '/hook input/ {f = 1} f && /(accept|drop|reject)/ {n++} /^[[:space:]]*}/ {f = 0} END {print n + 0}')"
  end "U-28"

  begin "U-34" # Finger 서비스 비활성화
  run "systemctl list-unit-files 2>/dev/null | grep -Ei 'finger'"
  run "grep -Els 'finger' /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null"
  run "ss -ltn 2>/dev/null | grep -E ':79\\b'"
  end "U-34"

  begin "U-35" # 공유 서비스에 대한 익명 접근 제한 설정
  run "grep -E '^(ftp|anonymous):' /etc/passwd | cut -d: -f1 | sed 's/^/ACCOUNT=/'"
  show_conf /etc/vsftpd.conf
  show_conf /etc/vsftpd/vsftpd.conf
  run "grep -Ei '<Anonymous' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null"
  run "systemctl is-active vsftpd proftpd 2>/dev/null"
  run "grep -Ei '^[[:space:]]*(guest ok|public|map to guest)[[:space:]]*=' /etc/samba/smb.conf 2>/dev/null"
  run "systemctl is-active smb smbd nmb 2>/dev/null"
  run "grep -Ev '^[[:space:]]*(#|$)' /etc/exports 2>/dev/null"
  end "U-35"

  begin "U-36" # r 계열 서비스 비활성화
  run "systemctl list-unit-files 2>/dev/null | grep -Ei 'rsh|rlogin|rexec'"
  run "grep -Hi 'disable' /etc/xinetd.d/rsh /etc/xinetd.d/rlogin /etc/xinetd.d/rexec 2>/dev/null"
  run "ss -ltn 2>/dev/null | grep -E ':(512|513|514)\\b'"
  end "U-36"

  begin "U-37" # crontab 설정파일 권한 설정 미흡
  hdr "stat crontab/at commands"
  for file in /usr/bin/crontab /usr/bin/at; do
    [ -e "$file" ] && stat -c 'KIND=cmd FILE=%n OWNER=%U GROUP=%G MODE=%a' "$file"
  done
  hdr "stat cron/at files"
  for file in /etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
    [ -e "$file" ] && stat -c 'KIND=conf FILE=%n OWNER=%U GROUP=%G MODE=%a' "$file"
  done
  find /etc/cron.d /var/spool/cron /var/spool/at -xdev -type f \
    -exec stat -c 'KIND=conf FILE=%n OWNER=%U GROUP=%G MODE=%a' {} + 2>/dev/null | head -n 50
  end "U-37"

  begin "U-38" # DoS 공격에 취약한 서비스 비활성화
  inet_check echo discard daytime chargen
  listen
  end "U-38"

  begin "U-39" # 불필요한 NFS 서비스 비활성화
  svc nfs-server nfs-kernel-server
  procs nfsd rpc.mountd rpc.statd rpc.lockd
  end "U-39"

  begin "U-40" # NFS 접근 통제
  svc nfs-server nfs-kernel-server
  procs nfsd
  show_conf /etc/exports
  stat_line /etc/exports
  end "U-40"

  begin "U-41" # 불필요한 automountd 제거
  svc autofs
  procs automount automountd
  end "U-41"

  begin "U-42" # 불필요한 RPC 서비스 비활성화
  inet_check rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd
  procs rpc.cmsd rpc.ttdbserverd sadmind rpc.rusersd rpc.walld rpc.sprayd rpc.rstatd rpc.nisd rpc.rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd
  end "U-42"

  begin "U-43" # NIS, NIS+ 점검
  svc ypserv ypbind ypxfrd yppasswdd
  procs ypserv ypbind ypxfrd rpc.yppasswdd rpc.ypupdated
  end "U-43"

  begin "U-44" # tftp, talk 서비스 비활성화
  svc tftp.socket tftp tftpd-hpa
  inet_check tftp talk ntalk
  listen
  end "U-44"

  begin "U-45" # 메일 서비스 버전 점검
  svc sendmail postfix exim4 exim
  procs sendmail master exim exim4
  run "postconf -d mail_version 2>/dev/null"
  run "exim -bV 2>/dev/null | head -n 1"
  run "rpm -q sendmail postfix exim 2>/dev/null | grep -v 'not installed'"
  pending_updates MAIL_PENDING_UPDATES 'sendmail[^/]*|postfix[^/]*|exim4[^/]*'
  end "U-45"

  begin "U-46" # 일반 사용자의 메일 서비스 실행 방지
  svc sendmail postfix exim4 exim
  procs sendmail master exim exim4
  run "grep -E '^O PrivacyOptions' /etc/mail/sendmail.cf 2>/dev/null"
  stat_line /usr/sbin/postsuper /usr/sbin/exiqgrep
  end "U-46"

  begin "U-47" # 스팸 메일 릴레이 제한
  svc sendmail postfix exim4 exim
  procs sendmail master exim exim4
  run "postconf smtpd_relay_restrictions smtpd_recipient_restrictions mynetworks 2>/dev/null"
  run "grep -Ec 'Relaying denied' /etc/mail/sendmail.cf 2>/dev/null | sed 's/^/SENDMAIL_RELAY_RULES=/'"
  run "grep -Eh 'promiscuous_relay' /etc/mail/sendmail.mc /etc/mail/sendmail.cf 2>/dev/null"
  run "grep -Ehs 'relay_from_hosts' /etc/exim4/exim4.conf.template /etc/exim4/update-exim4.conf.conf /etc/exim/exim.conf 2>/dev/null"
  end "U-47"

  begin "U-49" # DNS 보안 버전 패치
  svc named bind9
  procs named
  run "named -v 2>/dev/null"
  pending_updates DNS_PENDING_UPDATES 'bind9[^/]*|bind[^/]*'
  end "U-49"

  begin "U-50" # DNS ZoneTransfer 설정
  svc named bind9
  procs named
  run "grep -rEhs 'allow-transfer|xfrnets' /etc/named.conf /etc/named.rfc1912.zones /etc/bind/ 2>/dev/null"
  end "U-50"

  begin "U-59" # 안전한 SNMP 버전 사용
  svc snmpd
  procs snmpd
  snmp_conf
  end "U-59"

  begin "U-61" # SNMP Access Control 설정
  svc snmpd
  procs snmpd
  snmp_conf
  end "U-61"

  begin "U-64" # 주기적 보안 패치 및 벤더 권고사항 적용
  run "uname -r"
  if command -v apt >/dev/null 2>&1; then
    run "grep -h '^Start-Date' /var/log/apt/history.log 2>/dev/null | tail -n 5"
    run "apt list --upgradable 2>/dev/null | grep -ci security | sed 's/^/PENDING_SECURITY_UPDATES=/'"
  fi
  if command -v rpm >/dev/null 2>&1; then
    run "rpm -qa --last 2>/dev/null | head -n 5"
  fi
  end "U-64"

  begin "U-66" # 정책에 따른 시스템 로깅 설정
  run "systemctl is-active rsyslog syslog-ng 2>/dev/null"
  show_conf /etc/rsyslog.conf
  run "grep -Ehv '^[[:space:]]*(#|$)' /etc/rsyslog.d/*.conf 2>/dev/null"
  end "U-66"

  echo "[END]"
}

collect >"$OUT" 2>&1
chmod 600 "$OUT"
echo "점검이 끝났습니다. 결과 파일: $(pwd)/$OUT"
echo "이 파일을 웹 콘솔의 '신규 진단' 화면에 업로드하세요."

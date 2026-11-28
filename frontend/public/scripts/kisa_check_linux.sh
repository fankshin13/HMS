#!/usr/bin/env bash
# =============================================================================
# 시스템 취약점 진단 - Linux 표준 점검 스크립트
#   대상: CentOS / RHEL / Rocky / Ubuntu / Debian
#   기준: KISA 주요정보통신기반시설 기술적 취약점 분석·평가 (Unix 서버)
#
# 이 스크립트는 읽기 전용입니다. 설정을 바꾸지 않고 판정에 필요한 근거만 모아
# 현재 디렉터리에 <호스트명>_linux_<일시>.txt 파일로 저장합니다.
# 비밀번호 해시 등 비밀 값은 수집하지 않습니다.
#
# 실행: sudo bash kisa_check_linux.sh
# =============================================================================
set -u
export LC_ALL=C

SCRIPT_VERSION="1.0.0"
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

  begin "U-02" # 패스워드 복잡성 설정
  show_conf /etc/security/pwquality.conf
  run "grep -Eh 'pam_pwquality|pam_cracklib' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password 2>/dev/null"
  run "grep -E '^PASS_(MIN_LEN|MAX_DAYS|MIN_DAYS)' /etc/login.defs"
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

  begin "U-05" # root 홈, 패스 디렉터리 권한 및 패스 설정
  # sudo 의 secure_path 가 아니라 root 로그인 셸의 PATH 를 확인한다
  run "bash -lc 'echo PATH=\$PATH'"
  run "ls -ld /root"
  end "U-05"

  begin "U-06" # 파일 및 디렉터리 소유자 설정
  run "find / -xdev \\( -nouser -o -nogroup \\) -print 2>/dev/null | head -n 50"
  end "U-06"

  begin "U-07" # /etc/passwd 파일 소유자 및 권한 설정
  run "stat -c 'OWNER=%U MODE=%a FILE=%n' /etc/passwd"
  end "U-07"

  begin "U-08" # /etc/shadow 파일 소유자 및 권한 설정
  run "stat -c 'OWNER=%U MODE=%a FILE=%n' /etc/shadow"
  end "U-08"

  begin "U-19" # Finger 서비스 비활성화
  run "systemctl list-unit-files 2>/dev/null | grep -Ei 'finger'"
  run "grep -Els 'finger' /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null"
  run "ss -ltn 2>/dev/null | grep -E ':79\\b'"
  end "U-19"

  begin "U-20" # Anonymous FTP 비활성화
  run "grep -E '^(ftp|anonymous):' /etc/passwd | cut -d: -f1 | sed 's/^/ACCOUNT=/'"
  show_conf /etc/vsftpd.conf
  show_conf /etc/vsftpd/vsftpd.conf
  run "grep -Ei '<Anonymous' /etc/proftpd/proftpd.conf /etc/proftpd.conf 2>/dev/null"
  run "systemctl is-active vsftpd proftpd 2>/dev/null"
  end "U-20"

  begin "U-21" # r 계열 서비스 비활성화
  run "systemctl list-unit-files 2>/dev/null | grep -Ei 'rsh|rlogin|rexec'"
  run "grep -Hi 'disable' /etc/xinetd.d/rsh /etc/xinetd.d/rlogin /etc/xinetd.d/rexec 2>/dev/null"
  run "ss -ltn 2>/dev/null | grep -E ':(512|513|514)\\b'"
  end "U-21"

  begin "U-42" # 최신 보안패치 및 벤더 권고사항 적용
  run "uname -r"
  if command -v apt >/dev/null 2>&1; then
    run "grep -h '^Start-Date' /var/log/apt/history.log 2>/dev/null | tail -n 5"
    run "apt list --upgradable 2>/dev/null | grep -ci security | sed 's/^/PENDING_SECURITY_UPDATES=/'"
  fi
  if command -v rpm >/dev/null 2>&1; then
    run "rpm -qa --last 2>/dev/null | head -n 5"
  fi
  end "U-42"

  begin "U-43" # 로그의 정기적 검토 및 보고
  echo "MANUAL_REVIEW=로그 검토·보고 절차는 담당자 인터뷰로 확인"
  run "ls -l /var/log/secure /var/log/auth.log /var/log/messages /var/log/syslog 2>/dev/null"
  end "U-43"

  begin "U-72" # 정책에 따른 시스템 로깅 설정
  run "systemctl is-active rsyslog syslog-ng 2>/dev/null"
  show_conf /etc/rsyslog.conf
  run "grep -Ehv '^[[:space:]]*(#|$)' /etc/rsyslog.d/*.conf 2>/dev/null"
  end "U-72"

  echo "[END]"
}

collect >"$OUT" 2>&1
chmod 600 "$OUT"
echo "점검이 끝났습니다. 결과 파일: $(pwd)/$OUT"
echo "이 파일을 웹 콘솔의 '신규 진단' 화면에 업로드하세요."

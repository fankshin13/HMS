export interface MaskingConfig {
  maskIp: boolean;
  maskUsernames: boolean;
}

export interface MaskingResult {
  processedText: string;
  maskedIpCount: number;
  maskedUserCount: number;
}

// RFC 1918 사설 IP: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
export const PRIVATE_IP_REGEX =
  /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;

// "ACCOUNT=이름", "user: 이름", "계정=이름", 파일 소유자 "OWNER=이름"·"GROUP=이름" 형태의 계정 식별자
export const USERNAME_MASK_REGEX =
  /\b(user|account|owner|group|사용자|계정)(\s*[:=]\s*)([A-Za-z0-9_.$-]+)/gi;

// 홈 디렉터리 경로의 계정 이름 (/home/이름)
export const HOME_PATH_REGEX = /(\/home\/)([A-Za-z0-9_.-]+)/g;

// Windows 관리자·원격 데스크톱 그룹 구성원 "ADMIN_MEMBER=컴퓨터\이름" 의 이름 부분
export const ADMIN_MEMBER_REGEX =
  /\b((?:ADMIN|RDP)_MEMBER=(?:[^\s\\]+\\)?)([A-Za-z0-9_.$-]+)/g;

// Windows 사용자 폴더 경로의 계정 이름 (C:\Users\이름)
export const WINDOWS_PROFILE_REGEX = /([A-Za-z]:\\Users\\)([A-Za-z0-9_.$-]+)/g;

// 판정에 필요하고 조직을 식별하지 않는 OS 기본 계정은 그대로 둔다.
const SYSTEM_ACCOUNTS = new Set(
  [
    "root",
    "bin",
    "daemon",
    "adm",
    "lp",
    "sync",
    "shutdown",
    "halt",
    "mail",
    "operator",
    "games",
    "ftp",
    "anonymous",
    "nobody",
    "sshd",
    "www-data",
    "systemd-network",
    "systemd-resolve",
    "administrator",
    "guest",
    "defaultaccount",
    "wdagutilityaccount",
    "krbtgt",
    // 판정에 쓰이는 OS 기본 그룹
    "root",
    "wheel",
    "sys",
    "shadow",
    "crontab",
    "tty",
    "utmp",
    "staff",
    "users",
    "sudo",
    "nogroup",
    "systemd-journal",
    "ssl-cert",
    "postdrop",
    "smmsp",
    "named",
    "bind",
    "snmp",
    "unknown",
    // Windows 기본 프로필 폴더
    "public",
    "default",
  ].map((name) => name.toLowerCase()),
);

/**
 * 한 번의 업로드 안에서 같은 원본 값은 같은 가명으로 바꾼다(호스트 간 관계는 유지, 원본은 브라우저 밖으로 나가지 않음).
 * 원본↔가명 대응표는 이 객체(브라우저 메모리)에만 있다.
 */
export class MaskingSession {
  private readonly ips = new Map<string, string>();
  private readonly users = new Map<string, string>();

  constructor(private readonly config: MaskingConfig) {}

  mask(text: string): MaskingResult {
    let maskedIpCount = 0;
    let maskedUserCount = 0;
    let processedText = text;

    if (this.config.maskIp) {
      processedText = processedText.replace(PRIVATE_IP_REGEX, (ip) => {
        maskedIpCount += 1;
        return this.alias(this.ips, ip, "MASKED_IP");
      });
    }
    if (this.config.maskUsernames) {
      processedText = processedText.replace(
        USERNAME_MASK_REGEX,
        (match, label: string, sep: string, name: string) => {
          if (SYSTEM_ACCOUNTS.has(name.toLowerCase())) return match;
          maskedUserCount += 1;
          return `${label}${sep}${this.alias(this.users, name, "MASKED_USER")}`;
        },
      );
      // 같은 이름은 어디에 나오든 같은 가명이 되어야 소유자 비교 같은 판정이 유지된다
      processedText = processedText
        .replace(HOME_PATH_REGEX, (match, prefix: string, name: string) => {
          if (SYSTEM_ACCOUNTS.has(name.toLowerCase())) return match;
          maskedUserCount += 1;
          return `${prefix}${this.alias(this.users, name, "MASKED_USER")}`;
        })
        .replace(ADMIN_MEMBER_REGEX, (match, prefix: string, name: string) => {
          if (SYSTEM_ACCOUNTS.has(name.toLowerCase())) return match;
          maskedUserCount += 1;
          return `${prefix}${this.alias(this.users, name, "MASKED_USER")}`;
        })
        .replace(
          WINDOWS_PROFILE_REGEX,
          (match, prefix: string, name: string) => {
            if (SYSTEM_ACCOUNTS.has(name.toLowerCase())) return match;
            maskedUserCount += 1;
            return `${prefix}${this.alias(this.users, name, "MASKED_USER")}`;
          },
        );
    }
    return { processedText, maskedIpCount, maskedUserCount };
  }

  /** 미리보기용: 원본 → 가명 예시 (브라우저 화면에만 표시) */
  examples(limit = 5): { original: string; masked: string }[] {
    return [...this.ips, ...this.users]
      .slice(0, limit)
      .map(([original, masked]) => ({ original, masked }));
  }

  private alias(
    map: Map<string, string>,
    value: string,
    prefix: string,
  ): string {
    let alias = map.get(value);
    if (!alias) {
      alias = `${prefix}_${String(map.size + 1).padStart(3, "0")}`;
      map.set(value, alias);
    }
    return alias;
  }
}

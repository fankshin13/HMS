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

// "ACCOUNT=이름", "user: 이름", "계정=이름" 형태의 계정 식별자
export const USERNAME_MASK_REGEX =
  /\b(user|account|사용자|계정)(\s*[:=]\s*)([A-Za-z0-9_.$-]+)/gi;

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

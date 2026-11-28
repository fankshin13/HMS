/** 테스트용 표준 스크립트 결과 생성기 */
export function sampleLog({
  hostname = "web-01",
  os = "Linux",
  ip = "192.168.1.50",
  end = true,
  extra = "",
}: {
  hostname?: string;
  os?: "Linux" | "Windows";
  ip?: string;
  end?: boolean;
  extra?: string;
} = {}): string {
  return [
    `[START] OS=${os} HOSTNAME=${hostname} DATE=2026-11-27T09:00:00+0900 SCRIPT=kisa_check_${os.toLowerCase()} VERSION=1.0.0`,
    "[INFO] DISTRO=Ubuntu 24.04.5 LTS",
    `[INFO] IP=${ip}/24`,
    "",
    "==== U-01 BEGIN ====",
    "$ sshd -T | grep -Ei '^permitrootlogin'",
    "permitrootlogin no",
    "==== U-01 END ====",
    "==== U-04 BEGIN ====",
    "ACCOUNT=hong.gildong",
    "ACCOUNT=root",
    `peer 10.20.30.40 gateway ${ip} public 8.8.8.8 edge 172.15.0.1 172.31.255.1 172.32.0.1`,
    "==== U-04 END ====",
    extra,
    end ? "[END]" : "",
  ].join("\n");
}

import { describe, expect, it } from "vitest";
import { MaskingSession, PRIVATE_IP_REGEX } from "./masking";
import { sampleLog } from "./test-fixtures";

const both = { maskIp: true, maskUsernames: true };

describe("PRIVATE_IP_REGEX", () => {
  it.each(["10.0.0.1", "172.16.1.1", "172.31.255.255", "192.168.0.100"])(
    "matches private %s",
    (ip) => {
      expect(ip.match(PRIVATE_IP_REGEX)).toEqual([ip]);
    },
  );

  it.each(["8.8.8.8", "172.15.0.1", "172.32.0.1", "192.169.1.1", "11.0.0.1"])(
    "keeps public %s",
    (ip) => {
      expect(ip.match(PRIVATE_IP_REGEX)).toBeNull();
    },
  );
});

describe("MaskingSession", () => {
  it("masks private IPs and custom accounts but keeps public IPs and system accounts", () => {
    const { processedText, maskedIpCount, maskedUserCount } =
      new MaskingSession(both).mask(sampleLog());

    for (const secret of [
      "192.168.1.50",
      "10.20.30.40",
      "172.31.255.1",
      "hong.gildong",
    ]) {
      expect(processedText).not.toContain(secret);
    }
    for (const kept of [
      "8.8.8.8",
      "172.15.0.1",
      "172.32.0.1",
      "ACCOUNT=root",
      "HOSTNAME=web-01",
    ]) {
      expect(processedText).toContain(kept);
    }
    expect(processedText).toContain("ACCOUNT=MASKED_USER_001");
    expect(maskedIpCount).toBe(4); // 192.168.1.50 두 번, 10.20.30.40, 172.31.255.1
    expect(maskedUserCount).toBe(1);
  });

  it("masks the same account consistently in USER, OWNER, GROUP, home paths and admin members", () => {
    const session = new MaskingSession(both);
    const { processedText } = session.mask(
      [
        "USER=hong.gildong FILE=/home/hong.gildong/.bashrc OWNER=hong.gildong GROUP=hong.gildong MODE=644",
        "USER=root FILE=/root/.bashrc OWNER=root GROUP=root MODE=644",
        "FILE=/usr/bin/su OWNER=root GROUP=wheel MODE=4750",
        "ADMIN_MEMBER=WIN-SRV-01\\kim.admin CLASS=User SOURCE=Local",
        "ADMIN_MEMBER=WIN-SRV-01\\Administrator CLASS=User SOURCE=Local",
      ].join("\n"),
    );
    expect(processedText).not.toContain("hong.gildong");
    expect(processedText).not.toContain("kim.admin");
    expect(processedText).toContain(
      "USER=MASKED_USER_001 FILE=/home/MASKED_USER_001/.bashrc OWNER=MASKED_USER_001 GROUP=MASKED_USER_001",
    );
    expect(processedText).toContain("OWNER=root GROUP=root");
    expect(processedText).toContain("GROUP=wheel MODE=4750");
    expect(processedText).toContain(
      "ADMIN_MEMBER=WIN-SRV-01\\MASKED_USER_002 CLASS=User",
    );
    expect(processedText).toContain("ADMIN_MEMBER=WIN-SRV-01\\Administrator");
  });

  it("masks Remote Desktop members and Windows profile folders consistently", () => {
    const { processedText } = new MaskingSession(both).mask(
      [
        "RDP_MEMBER=WIN-SRV-01\\park.ops CLASS=User",
        "HOME_DIR=C:\\Users\\park.ops EVERYONE=False",
        "HOME_DIR=C:\\Users\\Administrator EVERYONE=False",
        "HOME_DIR=C:\\Users\\Public EVERYONE=True",
      ].join("\n"),
    );
    expect(processedText).not.toContain("park.ops");
    expect(processedText).toContain("RDP_MEMBER=WIN-SRV-01\\MASKED_USER_001");
    expect(processedText).toContain(
      "HOME_DIR=C:\\Users\\MASKED_USER_001 EVERYONE=False",
    );
    expect(processedText).toContain("C:\\Users\\Administrator");
    expect(processedText).toContain("C:\\Users\\Public");
  });

  it("uses the same alias for the same value across files in one upload", () => {
    const session = new MaskingSession(both);
    const a = session.mask("[INFO] IP=192.168.1.50/24").processedText;
    const b = session.mask(
      "gateway 192.168.1.50 other 192.168.1.51",
    ).processedText;
    expect(a).toBe("[INFO] IP=MASKED_IP_001/24");
    expect(b).toBe("gateway MASKED_IP_001 other MASKED_IP_002");
    expect(session.examples()).toEqual([
      { original: "192.168.1.50", masked: "MASKED_IP_001" },
      { original: "192.168.1.51", masked: "MASKED_IP_002" },
    ]);
  });

  it("leaves text untouched when masking is off", () => {
    const text = sampleLog();
    expect(
      new MaskingSession({ maskIp: false, maskUsernames: false }).mask(text),
    ).toEqual({
      processedText: text,
      maskedIpCount: 0,
      maskedUserCount: 0,
    });
  });
});

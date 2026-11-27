import "server-only";

// 서버 전용 설정. 클라이언트 번들에 포함되지 않는다.
function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`환경 변수 ${name} 이(가) 설정되지 않았습니다`);
  }
  return value;
}

export const serverEnv = {
  /** 초대 토큰 해시 솔트 (시크릿) */
  invitationTokenSalt: () => required("INVITATION_TOKEN_SALT"),
  /** 초대 링크와 매직 링크 복귀 주소에 쓰는 서비스 기본 주소 */
  appUrl: () => required("APP_URL").replace(/\/+$/, ""),
};

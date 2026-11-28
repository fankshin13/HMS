import path from "node:path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // 컨테이너 배포용 독립 실행 번들(.next/standalone). pnpm 작업 공간 루트 기준으로 의존성을 추적한다.
  output: "standalone",
  outputFileTracingRoot: path.join(__dirname, ".."),
};

export default nextConfig;

"use client";

import { useEffect } from "react";

/** 초대 토큰이 브라우저 방문 기록과 Referer 에 남지 않도록 주소창에서 지운다. */
export function StripTokenFromUrl() {
  useEffect(() => {
    const url = new URL(window.location.href);
    if (url.searchParams.has("token")) {
      url.searchParams.delete("token");
      window.history.replaceState(
        window.history.state,
        "",
        url.pathname + url.search,
      );
    }
  }, []);
  return null;
}

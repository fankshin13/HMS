"""원본 로그 읽기. 워커는 백엔드 전용 service role 키로 비공개 버킷을 읽는다."""

import os
from typing import Protocol
from urllib.parse import quote

import httpx

BUCKET = "diagnostic-raw"


class LogSource(Protocol):
    def read(self, storage_path: str) -> str: ...


class SupabaseStorageSource:
    def __init__(self, supabase_url: str, service_role_key: str) -> None:
        self._client = httpx.Client(
            base_url=f"{supabase_url.rstrip('/')}/storage/v1",
            headers={"Authorization": f"Bearer {service_role_key}", "apikey": service_role_key},
            timeout=30,
        )

    @classmethod
    def from_env(cls) -> "SupabaseStorageSource":
        url = os.environ.get("SUPABASE_URL", "")
        key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
        if not url or not key:
            raise RuntimeError("SUPABASE_URL 과 SUPABASE_SERVICE_ROLE_KEY 가 필요합니다")
        return cls(url, key)

    def read(self, storage_path: str) -> str:
        response = self._client.get(f"/object/{BUCKET}/{quote(storage_path)}")
        response.raise_for_status()
        return response.content.decode("utf-8", errors="replace")

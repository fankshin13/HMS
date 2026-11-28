"""Supabase Storage 접근. 워커는 백엔드 전용 service role 키로 비공개 버킷을 읽고 쓴다.

- diagnostic-raw: 원본 로그 읽기·영구 삭제
- reports: 조판한 보고서 업로드·삭제
"""

import os
from typing import Protocol
from urllib.parse import quote

import httpx

BUCKET = "diagnostic-raw"
REPORT_BUCKET = "reports"
DELETE_BATCH = 100


class LogSource(Protocol):
    def read(self, storage_path: str) -> str: ...


class ReportStore(Protocol):
    def put(self, path: str, content: bytes, content_type: str) -> None: ...

    def delete(self, paths: list[str]) -> None: ...


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

    def bucket(self, name: str) -> "SupabaseBucket":
        return SupabaseBucket(self._client, name)


class SupabaseBucket:
    """버킷 하나에 대한 업로드(덮어쓰기)·일괄 삭제. 없는 객체 삭제는 오류가 아니다."""

    def __init__(self, client: httpx.Client, name: str) -> None:
        self._client = client
        self._name = name

    def put(self, path: str, content: bytes, content_type: str) -> None:
        response = self._client.post(
            f"/object/{self._name}/{quote(path)}",
            content=content,
            headers={"Content-Type": content_type, "x-upsert": "true"},
        )
        response.raise_for_status()

    def delete(self, paths: list[str]) -> None:
        for start in range(0, len(paths), DELETE_BATCH):
            response = self._client.request(
                "DELETE",
                f"/object/{self._name}",
                json={"prefixes": paths[start : start + DELETE_BATCH]},
            )
            response.raise_for_status()

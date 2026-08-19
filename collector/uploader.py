"""Upload a completed capture to the fixed C2Sherlock cloud API."""

from __future__ import annotations

import hashlib
from pathlib import Path

import requests

from config import CONFIG


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def upload_capture(path: Path, session_id: str, upload_token: str, sha256: str) -> dict:
    url = f"{CONFIG.cloud_api_base}/collector/sessions/{session_id}/pcap"
    with path.open("rb") as file_obj:
        response = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {upload_token}",
                "X-Capture-SHA256": sha256,
            },
            files={"pcap": (path.name, file_obj, "application/octet-stream")},
            timeout=(CONFIG.upload_connect_timeout, CONFIG.upload_read_timeout),
        )
    if response.status_code != 202:
        try:
            detail = response.json().get("detail")
        except (ValueError, AttributeError):
            detail = response.text.strip()
        raise RuntimeError(f"云端接收失败（{response.status_code}）：{detail or '未知错误'}")
    return response.json()


def upload_chunk(
    path: Path,
    session_id: str,
    upload_token: str,
    sequence: int,
    sha256: str,
) -> dict:
    url = f"{CONFIG.cloud_api_base}/collector/sessions/{session_id}/chunks/{sequence}"
    with path.open("rb") as file_obj:
        response = requests.put(
            url,
            headers={
                "Authorization": f"Bearer {upload_token}",
                "X-Chunk-SHA256": sha256,
            },
            files={"pcap": (path.name, file_obj, "application/octet-stream")},
            timeout=(CONFIG.upload_connect_timeout, CONFIG.upload_read_timeout),
        )
    if response.status_code != 202:
        try:
            detail = response.json().get("detail")
        except (ValueError, AttributeError):
            detail = response.text.strip()
        raise RuntimeError(f"云端分片接收失败（{response.status_code}）：{detail or '未知错误'}")
    return response.json()


def finalize_capture(
    session_id: str,
    upload_token: str,
    total_chunks: int,
    total_bytes: int,
) -> dict:
    url = f"{CONFIG.cloud_api_base}/collector/sessions/{session_id}/finalize"
    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {upload_token}",
            "Content-Type": "application/json",
        },
        json={"total_chunks": total_chunks, "total_bytes": total_bytes},
        timeout=(CONFIG.upload_connect_timeout, CONFIG.upload_read_timeout),
    )
    if response.status_code != 202:
        try:
            detail = response.json().get("detail")
        except (ValueError, AttributeError):
            detail = response.text.strip()
        raise RuntimeError(f"云端结束会话失败（{response.status_code}）：{detail or '未知错误'}")
    return response.json()


"""Single-task state machine coordinating dumpcap, hashing and upload."""

from __future__ import annotations

import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from config import CONFIG
from dumpcap_manager import (
    DumpcapError,
    find_dumpcap,
    list_interfaces,
    probe_capture_access,
    start_dumpcap,
    stop_dumpcap,
    validate_capture_filter,
)
from models import CaptureStartRequest
from uploader import file_sha256, upload_capture


@dataclass
class CaptureTask:
    capture_id: str
    cloud_session_id: str
    upload_token: str = field(repr=False)
    output_path: Path
    max_duration_seconds: int
    max_file_size_mb: int
    started_at: float = field(default_factory=time.time)
    process: object | None = field(default=None, repr=False)
    status: str = "starting"
    sha256: str | None = None
    last_error: str | None = None


class CaptureCoordinator:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._task: CaptureTask | None = None
        self._environment_cache: dict | None = None
        self._environment_checked_at = 0.0

    def environment(self, *, force: bool = False) -> dict:
        with self._lock:
            if (
                not force
                and self._environment_cache is not None
                and time.monotonic() - self._environment_checked_at < 5
            ):
                return dict(self._environment_cache)
        path = find_dumpcap()
        interfaces = []
        error = None
        if path:
            try:
                interfaces = list_interfaces(path)
                probe_capture_access(path, interfaces[0].id)
            except DumpcapError as exc:
                error = str(exc)
        result = {
            "ready": bool(path and interfaces and not error),
            "dumpcap_available": bool(path),
            "npcap_available": bool(path and interfaces and not error),
            "requires_admin": bool(path and error),
            "dumpcap_path": str(path) if path else None,
            "interfaces": [item.model_dump() for item in interfaces],
            "environment_error": error,
        }
        with self._lock:
            self._environment_cache = result
            self._environment_checked_at = time.monotonic()
        return dict(result)

    def interfaces(self) -> list[dict]:
        path = find_dumpcap()
        if not path:
            raise DumpcapError("未找到 dumpcap.exe，请安装 Wireshark（包含 Npcap）")
        interfaces = list_interfaces(path)
        self.environment(force=True)
        return [item.model_dump() for item in interfaces]

    def start(self, payload: CaptureStartRequest) -> dict:
        with self._lock:
            if self._task and self._task.status not in {"completed", "capture_failed"}:
                raise DumpcapError("已有采集任务正在执行")
            path = find_dumpcap()
            if not path:
                raise DumpcapError("未找到 dumpcap.exe，请安装 Wireshark（包含 Npcap）")
            interfaces = {item.id: item for item in list_interfaces(path)}
            if payload.interface_id not in interfaces:
                raise DumpcapError("所选网卡不在当前 dumpcap 网卡列表中")
            capture_filter = validate_capture_filter(path, payload.capture_filter)
            capture_id = str(uuid.uuid4())
            output_path = CONFIG.data_dir / "captures" / capture_id / "capture.pcapng"
            task = CaptureTask(
                capture_id=capture_id,
                cloud_session_id=payload.cloud_session_id,
                upload_token=payload.upload_token,
                output_path=output_path,
                max_duration_seconds=payload.max_duration_seconds,
                max_file_size_mb=payload.max_file_size_mb,
            )
            self._task = task
            try:
                task.process = start_dumpcap(
                    path,
                    payload.interface_id,
                    capture_filter,
                    payload.max_duration_seconds,
                    payload.max_file_size_mb,
                    output_path,
                )
                task.status = "capturing"
            except Exception:
                self._task = None
                shutil.rmtree(output_path.parent, ignore_errors=True)
                raise
            threading.Thread(target=self._watch_process, args=(task,), daemon=True).start()
            return self.status()

    def stop(self) -> dict:
        with self._lock:
            task = self._task
            if not task:
                raise DumpcapError("当前没有采集任务")
            if task.status == "upload_failed":
                task.status = "hashing"
                task.last_error = None
                threading.Thread(target=self._finalize_and_upload, args=(task,), daemon=True).start()
                return self.status()
            if task.status in {"completed", "hashing", "uploading", "stopping"}:
                return self.status()
            task.status = "stopping"
            stop_dumpcap(task.process)
            return self.status()

    def status(self) -> dict:
        with self._lock:
            task = self._task
            base = self.environment()
            if not task:
                return {**base, "capture_status": "idle", "capture_id": None, "last_error": None}
            elapsed = max(0, int(time.time() - task.started_at))
            size = task.output_path.stat().st_size if task.output_path.exists() else 0
            return {
                **base,
                "capture_status": task.status,
                "capture_id": task.capture_id,
                "cloud_session_id": task.cloud_session_id,
                "elapsed_seconds": elapsed,
                "captured_bytes": size,
                "max_duration_seconds": task.max_duration_seconds,
                "max_file_size_mb": task.max_file_size_mb,
                "sha256": task.sha256,
                "last_error": task.last_error,
            }

    def shutdown(self) -> None:
        with self._lock:
            if self._task and self._task.process and self._task.process.poll() is None:
                stop_dumpcap(self._task.process)

    def _watch_process(self, task: CaptureTask) -> None:
        task.process.wait()
        with self._lock:
            if self._task is not task or task.status in {"completed", "uploading", "hashing"}:
                return
            if not task.output_path.exists() or task.output_path.stat().st_size == 0:
                task.status = "capture_failed"
                task.last_error = "dumpcap 未生成有效的 PCAPNG 文件"
                return
            task.status = "hashing"
        self._finalize_and_upload(task)

    def _finalize_and_upload(self, task: CaptureTask) -> None:
        try:
            if not task.output_path.exists() or task.output_path.stat().st_size == 0:
                raise RuntimeError("采集文件不存在或为空")
            task.sha256 = file_sha256(task.output_path)
            with self._lock:
                task.status = "uploading"
            upload_capture(task.output_path, task.cloud_session_id, task.upload_token, task.sha256)
            shutil.rmtree(task.output_path.parent, ignore_errors=True)
            with self._lock:
                task.status = "completed"
                task.upload_token = ""
                task.last_error = None
        except Exception as exc:
            with self._lock:
                task.status = "upload_failed"
                task.last_error = str(exc)


COORDINATOR = CaptureCoordinator()

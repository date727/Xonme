"""Coordinate rolling dumpcap files, reliable chunk upload and finalization."""

from __future__ import annotations

import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
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
from uploader import file_sha256, finalize_capture, upload_chunk


@dataclass
class CaptureTask:
    capture_id: str
    cloud_session_id: str
    upload_token: str = field(repr=False)
    output_path: Path
    max_duration_seconds: int
    max_file_size_mb: int
    started_at: float = field(default_factory=time.time)
    stopped_at: float | None = None
    process: object | None = field(default=None, repr=False)
    status: str = "starting"
    last_error: str | None = None
    uploaded_bytes: int = 0
    uploaded_chunks: int = 0
    pending_chunks: int = 0
    last_sync_at: str | None = None
    next_sequence: int = 0
    file_sequences: dict[Path, int] = field(default_factory=dict, repr=False)


class CaptureCoordinator:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._task: CaptureTask | None = None
        self._environment_cache: dict | None = None
        self._environment_checked_at = 0.0

    def environment(self, *, force: bool = False) -> dict:
        with self._lock:
            if not force and self._environment_cache is not None and time.monotonic() - self._environment_checked_at < 5:
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
                raise DumpcapError("未找到 dumpcap.exe，请重新启动控制器并在终端输入正确路径")
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
                task.process = start_dumpcap(path, payload.interface_id, capture_filter, payload.max_duration_seconds, payload.max_file_size_mb, output_path)
                task.status = "capturing"
            except Exception:
                self._task = None
                shutil.rmtree(output_path.parent, ignore_errors=True)
                raise
            threading.Thread(target=self._watch_and_upload, args=(task,), daemon=True).start()
            return self.status()

    def stop(self) -> dict:
        with self._lock:
            task = self._task
            if not task:
                raise DumpcapError("当前没有采集任务")
            if task.status == "upload_failed":
                if task.process and task.process.poll() is None:
                    stop_dumpcap(task.process)
                    task.stopped_at = task.stopped_at or time.time()
                task.status = "uploading_remaining"
                task.last_error = None
                threading.Thread(target=self._resume_upload, args=(task,), daemon=True).start()
                return self.status()
            if task.status in {"completed", "finalizing", "stopping", "uploading_remaining"}:
                return self.status()
            task.status = "stopping"
            stop_dumpcap(task.process)
            task.stopped_at = task.stopped_at or time.time()
            return self.status()

    def status(self) -> dict:
        with self._lock:
            task = self._task
            base = self.environment()
            if not task:
                return {**base, "capture_status": "idle", "capture_id": None, "last_error": None}
            files = self._capture_files(task)
            local_bytes = sum(path.stat().st_size for path in files if path.exists())
            return {
                **base,
                "capture_status": task.status,
                "capture_id": task.capture_id,
                "cloud_session_id": task.cloud_session_id,
                "elapsed_seconds": max(0, int((task.stopped_at or time.time()) - task.started_at)),
                "captured_bytes": task.uploaded_bytes + local_bytes,
                "uploaded_bytes": task.uploaded_bytes,
                "uploaded_chunks": task.uploaded_chunks,
                "pending_chunks": task.pending_chunks,
                "last_sync_at": task.last_sync_at,
                "max_duration_seconds": task.max_duration_seconds,
                "max_file_size_mb": task.max_file_size_mb,
                "last_error": task.last_error,
            }

    def shutdown(self) -> None:
        with self._lock:
            if self._task and self._task.process and self._task.process.poll() is None:
                stop_dumpcap(self._task.process)

    @staticmethod
    def _capture_files(task: CaptureTask) -> list[Path]:
        if not task.output_path.parent.exists():
            return []
        return sorted((path for path in task.output_path.parent.glob("*.pcapng") if path.is_file()), key=lambda path: (path.stat().st_mtime_ns, path.name))

    @staticmethod
    def _register_files(task: CaptureTask, files: list[Path]) -> None:
        for path in files:
            if path not in task.file_sequences:
                task.file_sequences[path] = task.next_sequence
                task.next_sequence += 1

    def _watch_and_upload(self, task: CaptureTask) -> None:
        try:
            while task.process.poll() is None:
                files = self._capture_files(task)
                self._register_files(task, files)
                self._upload_files(task, files[:-1], capture_running=True)
                total = task.uploaded_bytes + sum(path.stat().st_size for path in files if path.exists())
                if total >= task.max_file_size_mb * 1024 * 1024:
                    with self._lock:
                        task.status = "stopping"
                    stop_dumpcap(task.process)
                    break
                time.sleep(1)
            task.process.wait()
            with self._lock:
                if task.stopped_at is None:
                    task.stopped_at = time.time()
            self._resume_upload(task)
        except Exception as exc:
            if task.process and task.process.poll() is None:
                stop_dumpcap(task.process)
            with self._lock:
                if task.process and task.process.poll() is not None and task.stopped_at is None:
                    task.stopped_at = time.time()
                task.status = "upload_failed"
                task.last_error = str(exc) or "采集分片同步失败"

    def _resume_upload(self, task: CaptureTask) -> None:
        try:
            files = self._capture_files(task)
            if not files and task.uploaded_chunks == 0:
                raise RuntimeError("dumpcap 未生成有效的 PCAPNG 文件")
            self._register_files(task, files)
            with self._lock:
                task.status = "uploading_remaining"
            self._upload_files(task, files, capture_running=False)
            with self._lock:
                task.status = "finalizing"
            finalize_capture(task.cloud_session_id, task.upload_token, task.uploaded_chunks, task.uploaded_bytes)
            with self._lock:
                task.status = "completed"
                if task.stopped_at is None:
                    task.stopped_at = time.time()
                task.upload_token = ""
                task.pending_chunks = 0
                task.last_error = None
            shutil.rmtree(task.output_path.parent, ignore_errors=True)
        except Exception as exc:
            with self._lock:
                task.status = "upload_failed"
                task.last_error = str(exc) or "剩余分片同步失败"

    def _upload_files(self, task: CaptureTask, files: list[Path], *, capture_running: bool) -> None:
        pending = [path for path in files if path.exists()]
        with self._lock:
            task.pending_chunks = len(pending)
        for path in pending:
            sequence = task.file_sequences[path]
            size = path.stat().st_size
            if size < 4:
                continue
            with self._lock:
                task.status = "capturing_uploading" if capture_running else "uploading_remaining"
            digest = file_sha256(path)
            last_error = None
            for attempt in range(5):
                try:
                    upload_chunk(path, task.cloud_session_id, task.upload_token, sequence, digest)
                    last_error = None
                    break
                except Exception as exc:
                    last_error = exc
                    with self._lock:
                        task.status = "sync_retrying"
                        task.last_error = str(exc)
                    time.sleep(min(30, 2 ** attempt))
            if last_error is not None:
                raise last_error
            path.unlink(missing_ok=True)
            with self._lock:
                task.uploaded_bytes += size
                task.uploaded_chunks += 1
                task.pending_chunks = max(0, task.pending_chunks - 1)
                task.last_sync_at = datetime.now().astimezone().isoformat()
                task.last_error = None
                if capture_running:
                    task.status = "capturing"


COORDINATOR = CaptureCoordinator()

"""Persistence, token validation and background analysis for collector uploads."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import statistics
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

from fastapi import HTTPException, UploadFile
from starlette.datastructures import Headers

from app.database import (
    CollectorChunk,
    CollectorEvent,
    CollectorSession,
    User,
    get_session_factory,
    local_database_time,
)


APP_ROOT = Path(__file__).resolve().parent.parent
COLLECTOR_UPLOAD_DIR = APP_ROOT / "data" / "collector_uploads"
ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".cap"}
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}
TERMINAL_STATUSES = {"completed", "failed", "expired"}
_EXECUTOR = ThreadPoolExecutor(
    max_workers=max(1, int(os.getenv("COLLECTOR_ANALYSIS_WORKERS", "1"))),
    thread_name_prefix="collector-analysis",
)
LOGGER = logging.getLogger(__name__)


def _token_ttl_seconds() -> int:
    return max(60, int(os.getenv("COLLECTOR_TOKEN_TTL_SECONDS", "5400")))


def _max_pcap_bytes() -> int:
    return max(1024, int(os.getenv("MAX_PCAP_BYTES", str(100 * 1024 * 1024))))


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_collector_session(user: User, model_id: str | None) -> tuple[CollectorSession, str]:
    raw_token = secrets.token_urlsafe(32)
    now = local_database_time()
    record = CollectorSession(
        id=str(uuid.uuid4()),
        user_id=user.id,
        upload_token_hash=_hash_token(raw_token),
        token_expires_at=now + timedelta(seconds=_token_ttl_seconds()),
        status="awaiting_chunks",
        model_id=model_id,
    )
    with get_session_factory()() as db:
        db.add(record)
        db.commit()
        db.refresh(record)
        db.expunge(record)
    return record, raw_token


def get_owned_collector_session(session_id: str, user_id: int) -> CollectorSession | None:
    with get_session_factory()() as db:
        record = (
            db.query(CollectorSession)
            .filter(CollectorSession.id == session_id, CollectorSession.user_id == user_id)
            .one_or_none()
        )
        if record:
            db.expunge(record)
        return record


def _latest_detection_payload(db, session_id: str) -> dict:
    event = (
        db.query(CollectorEvent)
        .filter(
            CollectorEvent.session_id == session_id,
            CollectorEvent.event_type == "detection_update",
        )
        .order_by(CollectorEvent.id.desc())
        .first()
    )
    return dict(event.payload_json) if event and isinstance(event.payload_json, dict) else {}


def collector_session_snapshot(record: CollectorSession) -> dict:
    """Return browser status plus progress derived from the append-only chunk table."""

    with get_session_factory()() as db:
        received_chunks, received_bytes = _chunk_totals(db, record.id)
        detection = _latest_detection_payload(db, record.id)
    return {
        "session_id": record.id,
        "status": record.status,
        "current_step": record.current_step,
        "original_filename": record.original_filename,
        "file_size": record.file_size,
        "sha256": record.sha256,
        "analysis_record_id": record.analysis_record_id,
        "error_message": record.error_message,
        "received_chunks": received_chunks,
        "received_bytes": received_bytes,
        "analyzed_bytes": detection.get("analyzed_bytes"),
        "connection_count": detection.get("connection_count"),
        "suspicious_count": detection.get("suspicious_count"),
        "last_analyzed_at": detection.get("last_analyzed_at"),
        "recent_alerts": detection.get("recent_alerts", []),
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "completed_at": record.completed_at,
    }


def _authorize_chunk_session(
    session_id: str,
    bearer_token: str,
    *,
    allowed_statuses: set[str] | None = None,
) -> CollectorSession:
    with get_session_factory()() as db:
        record = db.get(CollectorSession, session_id)
        if not record or not secrets.compare_digest(
            record.upload_token_hash, _hash_token(bearer_token)
        ):
            raise HTTPException(status_code=401, detail="上传令牌无效")
        now = local_database_time()
        if record.token_expires_at < now:
            record.status = "expired"
            record.completed_at = now
            db.commit()
            raise HTTPException(status_code=401, detail="上传令牌已过期")
        permitted = allowed_statuses or {"awaiting_chunks", "receiving"}
        if record.status not in permitted:
            raise HTTPException(status_code=409, detail="采集会话已结束或不允许继续上传")
        db.expunge(record)
        return record


def _validate_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise HTTPException(status_code=422, detail="分片 SHA-256 格式无效")
    return normalized


def _chunk_totals(db, session_id: str) -> tuple[int, int]:
    rows = db.query(CollectorChunk.file_size).filter(CollectorChunk.session_id == session_id).all()
    return len(rows), sum(int(row[0]) for row in rows)


def save_collector_chunk(
    session_id: str,
    bearer_token: str,
    sequence: int,
    upload: UploadFile,
    supplied_sha256: str | None,
) -> tuple[CollectorChunk, bool, int, int]:
    """Accept one complete ring-buffer file with retry-safe sequence semantics."""

    if sequence < 0 or sequence > 9999:
        raise HTTPException(status_code=422, detail="分片序号超出允许范围")
    _authorize_chunk_session(session_id, bearer_token)
    expected_sha256 = _validate_sha256(supplied_sha256)
    if expected_sha256 is None:
        raise HTTPException(status_code=422, detail="缺少分片 SHA-256")
    with get_session_factory()() as db:
        existing = (
            db.query(CollectorChunk)
            .filter(CollectorChunk.session_id == session_id, CollectorChunk.sequence == sequence)
            .one_or_none()
        )
        if existing:
            if expected_sha256 and not secrets.compare_digest(existing.sha256, expected_sha256):
                raise HTTPException(status_code=409, detail="相同分片序号对应的 SHA-256 不一致")
            totals = _chunk_totals(db, session_id)
            db.expunge(existing)
            return existing, True, totals[0], totals[1]

    filename = _safe_filename(upload.filename or f"chunk-{sequence:06d}.pcapng")
    suffix = Path(filename).suffix.lower()
    session_dir = COLLECTOR_UPLOAD_DIR / session_id
    chunks_dir = session_dir / "chunks"
    final_path = chunks_dir / f"chunk-{sequence:06d}{suffix}"
    part_path = final_path.with_suffix(final_path.suffix + ".part")
    chunks_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    magic = b""
    try:
        with part_path.open("xb") as target:
            while chunk := upload.file.read(1024 * 1024):
                size += len(chunk)
                if size > _max_pcap_bytes():
                    raise HTTPException(status_code=413, detail="单个分片超过服务器大小限制")
                if not magic:
                    magic = chunk[:4]
                digest.update(chunk)
                target.write(chunk)
        if size < 4 or magic not in PCAP_MAGIC:
            raise HTTPException(status_code=415, detail="分片不是有效的 PCAP/PCAPNG 格式")
        actual_sha256 = digest.hexdigest()
        if expected_sha256 and not secrets.compare_digest(expected_sha256, actual_sha256):
            raise HTTPException(status_code=422, detail="分片 SHA-256 校验失败")
        with get_session_factory()() as db:
            _, current_bytes = _chunk_totals(db, session_id)
            if current_bytes + size > _max_pcap_bytes():
                raise HTTPException(status_code=413, detail="采集会话总流量超过服务器大小限制")
            final_path.parent.mkdir(parents=True, exist_ok=True)
            part_path.replace(final_path)
            stored = CollectorChunk(
                session_id=session_id,
                sequence=sequence,
                sha256=actual_sha256,
                file_size=size,
                storage_path=str(final_path),
            )
            db.add(stored)
            record = db.get(CollectorSession, session_id)
            record.status = "receiving"
            record.updated_at = local_database_time()
            db.flush()
            received_chunks, received_bytes = _chunk_totals(db, session_id)
            progress = {
                "sequence": sequence,
                "received_chunks": received_chunks,
                "uploaded_bytes": received_bytes,
                "updated_at": record.updated_at.isoformat(),
            }
            _append_event(db, record, "chunk_received", progress)
            _append_event(db, record, "sync_progress", progress)
            db.commit()
            db.refresh(stored)
            db.expunge(stored)
        _EXECUTOR.submit(_run_realtime_detection, session_id)
        return stored, False, received_chunks, received_bytes
    except Exception:
        part_path.unlink(missing_ok=True)
        if final_path.exists():
            with get_session_factory()() as db:
                recorded = (
                    db.query(CollectorChunk)
                    .filter(CollectorChunk.session_id == session_id, CollectorChunk.sequence == sequence)
                    .one_or_none()
                )
            if not recorded:
                final_path.unlink(missing_ok=True)
        raise


def _run_realtime_detection(session_id: str) -> None:
    """Inspect the last five minutes of chunks and emit provisional alerts."""

    try:
        from scapy.all import IP, IPv6, TCP, UDP, PcapReader
    except ImportError:
        return
    with get_session_factory()() as db:
        cutoff = local_database_time() - timedelta(minutes=5)
        chunks = (
            db.query(CollectorChunk)
            .filter(
                CollectorChunk.session_id == session_id,
                CollectorChunk.received_at >= cutoff,
            )
            .order_by(CollectorChunk.sequence)
            .all()
        )
    groups: dict[tuple[str, str, int, str], dict] = {}
    checked_connections = 0
    for chunk in chunks:
        try:
            with PcapReader(chunk.storage_path) as packets:
                for packet in packets:
                    network = packet.getlayer(IP) or packet.getlayer(IPv6)
                    if network is None:
                        continue
                    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
                    if transport is None:
                        continue
                    proto = "tcp" if packet.haslayer(TCP) else "udp"
                    source = str(network.src)
                    destination = str(network.dst)
                    destination_port = int(transport.dport)
                    key = (source, destination, destination_port, proto)
                    entry = groups.setdefault(key, {"times": [], "bytes": 0})
                    entry["bytes"] += len(packet)
                    if proto == "tcp":
                        flags = int(transport.flags)
                        if not (flags & 0x02) or flags & 0x10:
                            continue
                    entry["times"].append(float(packet.time))
                    checked_connections += 1
        except (OSError, ValueError):
            continue

    alerts = []
    for (source, destination, port, proto), entry in groups.items():
        times = sorted(entry["times"])
        count = len(times)
        if count < 4:
            continue
        intervals = [later - earlier for earlier, later in zip(times, times[1:]) if later > earlier]
        periodic = False
        median_interval = 0.0
        if len(intervals) >= 3:
            median_interval = statistics.median(intervals)
            mean_interval = statistics.mean(intervals)
            variation = statistics.pstdev(intervals) / mean_interval if mean_interval > 0 else 1.0
            periodic = 5 <= median_interval <= 600 and variation <= 0.25
        average_bytes = entry["bytes"] / max(count, 1)
        repeated_small = count >= 10 and average_bytes <= 4096
        if not periodic and not repeated_small:
            continue
        score = min(95, (45 if periodic else 20) + min(35, count * 2) + (15 if repeated_small else 0))
        reasons = []
        if periodic:
            reasons.append(f"约 {median_interval:.1f} 秒周期")
        if repeated_small:
            reasons.append("重复小流量连接")
        alerts.append(
            {
                "source": source,
                "destination": f"{destination}:{port}",
                "severity": "high" if score >= 80 else "medium",
                "score": score,
                "engines": ["实时周期规则", "固定目标统计"],
                "summary": "、".join(reasons),
                "connection_count": count,
                "protocol": proto,
            }
        )
    alerts.sort(key=lambda item: item["score"], reverse=True)
    payload = {
        "status": "analyzing",
        "analyzed_bytes": sum(int(chunk.file_size) for chunk in chunks),
        "connection_count": checked_connections,
        "suspicious_count": len(alerts),
        "last_analyzed_at": local_database_time().isoformat(),
        "recent_alerts": alerts[:3],
    }
    with get_session_factory()() as db:
        record = db.get(CollectorSession, session_id)
        if not record or record.status not in {"awaiting_chunks", "receiving"}:
            return
        _append_event(db, record, "detection_update", payload)
        if alerts:
            _append_event(
                db,
                record,
                "suspicious_connection",
                payload,
            )
        db.commit()


def _mergecap_executable() -> str:
    configured = os.getenv("MERGECAP_PATH", "").strip()
    located = configured or shutil.which("mergecap") or ""
    if not located:
        raise RuntimeError("云端未安装 mergecap，请安装 wireshark-common 或配置 MERGECAP_PATH")
    return located


def finalize_collector_session(
    session_id: str,
    bearer_token: str,
    *,
    total_chunks: int,
    total_bytes: int,
) -> CollectorSession:
    """Validate the chunk manifest and schedule one final merge and analysis."""

    retryable_statuses = {
        "awaiting_chunks", "receiving", "finalizing", "merging", "queued", "analyzing", "completed"
    }
    _authorize_chunk_session(session_id, bearer_token, allowed_statuses=retryable_statuses)
    with get_session_factory()() as db:
        record = db.get(CollectorSession, session_id)
        chunks = (
            db.query(CollectorChunk)
            .filter(CollectorChunk.session_id == session_id)
            .order_by(CollectorChunk.sequence)
            .all()
        )
        sequences = [chunk.sequence for chunk in chunks]
        if len(chunks) != total_chunks or sequences != list(range(total_chunks)):
            raise HTTPException(status_code=409, detail="分片尚未全部上传或序号不连续")
        actual_bytes = sum(int(chunk.file_size) for chunk in chunks)
        if actual_bytes != total_bytes:
            raise HTTPException(status_code=409, detail="分片总大小与本地清单不一致")
        if record.status in {"finalizing", "merging", "queued", "analyzing", "completed"}:
            db.expunge(record)
            return record
        record.status = "finalizing"
        record.file_size = actual_bytes
        record.updated_at = local_database_time()
        _append_event(
            db,
            record,
            "finalizing",
            {"total_chunks": total_chunks, "total_bytes": actual_bytes},
        )
        db.commit()
        db.refresh(record)
        db.expunge(record)
    _EXECUTOR.submit(_merge_and_analyze, session_id)
    return record


def _merge_and_analyze(session_id: str) -> None:
    with get_session_factory()() as db:
        record = db.get(CollectorSession, session_id)
        chunks = (
            db.query(CollectorChunk)
            .filter(CollectorChunk.session_id == session_id)
            .order_by(CollectorChunk.sequence)
            .all()
        )
        if not record or not chunks:
            return
        # SQLAlchemy expires ORM attributes on commit. Copy every value needed by
        # the background job before the database session is committed/closed.
        chunk_paths = [str(chunk.storage_path) for chunk in chunks]
        session_dir = COLLECTOR_UPLOAD_DIR / session_id
        merged_path = session_dir / "merged.pcapng"
        record.status = "merging"
        record.updated_at = local_database_time()
        _append_event(db, record, "merging", {"total_chunks": len(chunks)})
        db.commit()
    try:
        if len(chunk_paths) == 1:
            shutil.copyfile(chunk_paths[0], merged_path)
        else:
            command = [_mergecap_executable(), "-w", str(merged_path), *chunk_paths]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(60, len(chunks) * 10),
                check=False,
            )
            if result.returncode != 0 or not merged_path.is_file():
                detail = (result.stderr or result.stdout or "").strip()
                raise RuntimeError(detail or "mergecap 合并流量分片失败")
        digest = hashlib.sha256()
        with merged_path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        with get_session_factory()() as db:
            record = db.get(CollectorSession, session_id)
            record.status = "queued"
            record.original_filename = "online-monitoring.pcapng"
            record.storage_path = str(merged_path)
            record.file_size = merged_path.stat().st_size
            record.sha256 = digest.hexdigest()
            record.upload_consumed_at = local_database_time()
            record.updated_at = local_database_time()
            _append_event(db, record, "merged", {"file_size": record.file_size, "sha256": record.sha256})
            db.commit()
        _run_analysis(session_id)
    except Exception as exc:
        LOGGER.exception("Collector session %s failed while merging chunks", session_id)
        update_session(
            session_id,
            status="failed",
            error_message="云端整理流量数据失败，请检查 mergecap 配置后重新发起监测",
            event_type="failed",
            event_payload={"message": "云端整理流量数据失败，请稍后重新发起监测"},
        )


def recover_interrupted_sessions() -> None:
    """Recover stale upload claims and terminate jobs lost during a restart."""

    now = local_database_time()
    with get_session_factory()() as db:
        uploading = db.query(CollectorSession).filter(
            CollectorSession.status == "uploading",
            CollectorSession.upload_consumed_at.is_(None),
        ).all()
        for record in uploading:
            record.status = "awaiting_chunks" if record.token_expires_at >= now else "expired"
            record.updated_at = now
            if record.status == "expired":
                record.completed_at = now
        interrupted = db.query(CollectorSession).filter(
            CollectorSession.status.in_(["finalizing", "merging", "queued", "analyzing"])
        ).all()
        for record in interrupted:
            record.status = "failed"
            record.error_message = "云端服务重启导致分析中断，请重新发起一次采集任务"
            record.updated_at = now
            record.completed_at = now
            _append_event(db, record, "failed", {"message": record.error_message})
        db.commit()


def _append_event(db, record: CollectorSession, event_type: str, payload: dict) -> None:
    db.add(CollectorEvent(session_id=record.id, event_type=event_type, payload_json=payload))


def update_session(
    session_id: str,
    *,
    status: str | None = None,
    current_step: str | None = None,
    error_message: str | None = None,
    analysis_record_id: int | None = None,
    event_type: str | None = None,
    event_payload: dict | None = None,
) -> None:
    with get_session_factory()() as db:
        record = db.get(CollectorSession, session_id)
        if not record:
            return
        if status is not None:
            record.status = status
        if current_step is not None:
            record.current_step = current_step
        if error_message is not None:
            record.error_message = error_message[:2000]
        if analysis_record_id is not None:
            record.analysis_record_id = analysis_record_id
        record.updated_at = local_database_time()
        if status in TERMINAL_STATUSES:
            record.completed_at = local_database_time()
        if event_type:
            _append_event(db, record, event_type, event_payload or {})
        db.commit()


def _safe_filename(filename: str | None) -> str:
    raw_name = (filename or "capture.pcapng").replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[^0-9A-Za-z_.\-一-鿿]+", "_", raw_name).strip("._")
    name = name[:255] or "capture.pcapng"
    suffix = Path(name).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=415, detail="仅支持 .pcap、.pcapng 或 .cap 文件")
    return name[:255]


def _claim_upload(session_id: str, bearer_token: str) -> CollectorSession:
    with get_session_factory()() as db:
        token_hash = _hash_token(bearer_token)
        record = db.get(CollectorSession, session_id)
        if not record or not secrets.compare_digest(record.upload_token_hash, token_hash):
            raise HTTPException(status_code=401, detail="上传令牌无效")
        now = local_database_time()
        if record.token_expires_at < now:
            record.status = "expired"
            record.completed_at = now
            db.commit()
            raise HTTPException(status_code=401, detail="上传令牌已过期")
        claimed = (
            db.query(CollectorSession)
            .filter(
                CollectorSession.id == session_id,
                CollectorSession.upload_token_hash == token_hash,
                CollectorSession.status.in_(["awaiting_upload", "awaiting_chunks"]),
                CollectorSession.upload_consumed_at.is_(None),
                CollectorSession.token_expires_at >= now,
            )
            .update(
                {CollectorSession.status: "uploading", CollectorSession.updated_at: now},
                synchronize_session=False,
            )
        )
        if claimed != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="该上传令牌已使用或会话状态不允许上传")
        db.commit()
        record = db.get(CollectorSession, session_id)
        db.refresh(record)
        db.expunge(record)
        return record


def _find_already_accepted(
    session_id: str, bearer_token: str, supplied_sha256: str | None
) -> CollectorSession | None:
    """Confirm a retry when the first 202 response was lost after acceptance."""

    if not supplied_sha256:
        return None
    with get_session_factory()() as db:
        record = db.get(CollectorSession, session_id)
        if not record or not record.upload_consumed_at or not record.sha256:
            return None
        if not secrets.compare_digest(record.upload_token_hash, _hash_token(bearer_token)):
            return None
        if not secrets.compare_digest(record.sha256, supplied_sha256.lower()):
            return None
        db.expunge(record)
        return record


def _release_upload_claim(session_id: str, message: str) -> None:
    with get_session_factory()() as db:
        record = db.get(CollectorSession, session_id)
        if not record or record.upload_consumed_at or record.status != "uploading":
            return
        record.status = "awaiting_chunks"
        record.error_message = message[:2000]
        record.updated_at = local_database_time()
        db.commit()


def save_collector_upload(
    session_id: str,
    bearer_token: str,
    upload: UploadFile,
    supplied_sha256: str | None,
) -> CollectorSession:
    filename = _safe_filename(upload.filename)
    already_accepted = _find_already_accepted(session_id, bearer_token, supplied_sha256)
    if already_accepted:
        return already_accepted
    record = _claim_upload(session_id, bearer_token)
    session_dir = COLLECTOR_UPLOAD_DIR / session_id
    part_path = session_dir / f"{filename}.part"
    final_path = session_dir / filename
    try:
        session_dir.mkdir(parents=True, exist_ok=False)
        digest = hashlib.sha256()
        size = 0
        magic = b""
        with part_path.open("xb") as target:
            while chunk := upload.file.read(1024 * 1024):
                size += len(chunk)
                if size > _max_pcap_bytes():
                    raise HTTPException(status_code=413, detail="PCAP 文件超过服务器大小限制")
                if not magic:
                    magic = chunk[:4]
                digest.update(chunk)
                target.write(chunk)
        if size < 4 or magic not in PCAP_MAGIC:
            raise HTTPException(status_code=415, detail="文件不是有效的 PCAP/PCAPNG 格式")
        actual_sha256 = digest.hexdigest()
        if supplied_sha256 and not secrets.compare_digest(supplied_sha256.lower(), actual_sha256):
            raise HTTPException(status_code=422, detail="上传文件 SHA-256 校验失败")
        part_path.replace(final_path)
        now = local_database_time()
        with get_session_factory()() as db:
            stored = db.get(CollectorSession, session_id)
            if not stored:
                raise HTTPException(status_code=404, detail="采集会话不存在")
            stored.status = "queued"
            stored.upload_consumed_at = now
            stored.original_filename = filename
            stored.storage_path = str(final_path)
            stored.file_size = size
            stored.sha256 = actual_sha256
            stored.error_message = None
            stored.updated_at = now
            _append_event(db, stored, "uploaded", {"file_size": size, "sha256": actual_sha256})
            db.commit()
            db.refresh(stored)
            db.expunge(stored)
            record = stored
    except Exception as exc:
        shutil.rmtree(session_dir, ignore_errors=True)
        _release_upload_claim(session_id, str(getattr(exc, "detail", exc)))
        raise
    _EXECUTOR.submit(_run_analysis, session_id)
    return record


def _parse_sse_blocks(buffer: str) -> tuple[list[tuple[str, str]], str]:
    normalized = buffer.replace("\r\n", "\n")
    parts = normalized.split("\n\n")
    remainder = parts.pop() or ""
    events: list[tuple[str, str]] = []
    for part in parts:
        event_type = "message"
        data_lines: list[str] = []
        for line in part.splitlines():
            if line.startswith("event:"):
                event_type = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].strip())
        events.append((event_type, "\n".join(data_lines)))
    return events, remainder


def _run_analysis(session_id: str) -> None:
    """Consume the existing streaming analysis pipeline without duplicating it."""

    with get_session_factory()() as db:
        record = db.get(CollectorSession, session_id)
        if not record or not record.storage_path:
            return
        source_path = Path(record.storage_path)
        filename = record.original_filename or "capture.pcapng"
        model_id = record.model_id
        user = db.get(User, record.user_id)
        if not user:
            update_session(
                session_id,
                status="failed",
                error_message="采集会话所属用户不存在",
                event_type="failed",
                event_payload={"message": "采集会话所属用户不存在"},
            )
            return
        db.expunge(user)
    update_session(session_id, status="analyzing", event_type="analysis_started")

    async def consume() -> None:
        from app.main import analyze_pcap_stream

        persistent_record_id: int | None = None
        result_received = False
        with source_path.open("rb") as file_obj:
            upload = UploadFile(file=file_obj, filename=filename, headers=Headers())
            response = await analyze_pcap_stream(
                pcap=upload,
                model_id=model_id,
                analysis_id=f"collector-{session_id}",
                user=user,
            )
            buffer = ""
            async for chunk in response.body_iterator:
                buffer += chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk
                parsed, buffer = _parse_sse_blocks(buffer)
                for event_type, data in parsed:
                    if event_type == "analysis_created":
                        payload = json.loads(data)
                        persistent_record_id = payload.get("analysis_record_id")
                        if persistent_record_id:
                            update_session(
                                session_id,
                                analysis_record_id=persistent_record_id,
                                event_type="analysis_created",
                                event_payload={"analysis_record_id": persistent_record_id},
                            )
                    elif event_type == "step":
                        update_session(
                            session_id,
                            current_step=data,
                            event_type="step",
                            event_payload={"step": data},
                        )
                    elif event_type == "result":
                        payload = json.loads(data)
                        analysis_record_id = payload.get("analysis_record_id")
                        if not analysis_record_id:
                            raise RuntimeError("分析已完成，但未生成可恢复的用户任务记录")
                        update_session(
                            session_id,
                            status="completed",
                            analysis_record_id=analysis_record_id,
                            event_type="completed",
                            event_payload={"analysis_record_id": analysis_record_id},
                        )
                        result_received = True
                    elif event_type in {"error", "cancelled"}:
                        update_session(
                            session_id,
                            status="failed",
                            error_message=data,
                            event_type="failed",
                            event_payload={"message": data},
                        )
            # Streaming transports can occasionally lose the final result frame
            # after the report has already been committed. Treat the database as
            # the source of truth and recover that terminal state here.
            if not result_received and persistent_record_id:
                from app.database import get_analysis_record_for_user

                persisted = get_analysis_record_for_user(persistent_record_id, user.id)
                if persisted and persisted.get("status") == "completed":
                    update_session(
                        session_id,
                        status="completed",
                        analysis_record_id=persistent_record_id,
                        event_type="completed",
                        event_payload={"analysis_record_id": persistent_record_id},
                    )
                elif persisted and persisted.get("status") in {"failed", "cancelled"}:
                    message = "完整分析未能成功完成，请重新发起在线监测"
                    update_session(
                        session_id,
                        status="failed",
                        error_message=message,
                        event_type="failed",
                        event_payload={"message": message},
                    )

    try:
        asyncio.run(consume())
    except Exception as exc:
        update_session(
            session_id,
            status="failed",
            error_message=str(exc) or "分析任务执行失败",
            event_type="failed",
            event_payload={"message": str(exc) or "分析任务执行失败"},
        )
    finally:
        shutil.rmtree(source_path.parent, ignore_errors=True)


def iter_session_events(session_id: str, user_id: int, after_id: int = 0) -> Iterator[str]:
    """Poll persisted events and emit SSE heartbeats until the session ends."""

    last_id = max(0, after_id)
    idle_ticks = 0
    while True:
        with get_session_factory()() as db:
            record = (
                db.query(CollectorSession)
                .filter(CollectorSession.id == session_id, CollectorSession.user_id == user_id)
                .one_or_none()
            )
            if not record:
                yield "event: error\ndata: {\"message\":\"采集会话不存在\"}\n\n"
                return
            events = (
                db.query(CollectorEvent)
                .filter(CollectorEvent.session_id == session_id, CollectorEvent.id > last_id)
                .order_by(CollectorEvent.id)
                .all()
            )
            terminal = record.status in TERMINAL_STATUSES
            for event in events:
                last_id = event.id
                payload = json.dumps(event.payload_json, ensure_ascii=False)
                yield f"id: {event.id}\nevent: {event.event_type}\ndata: {payload}\n\n"
            if terminal and not events:
                return
        idle_ticks += 1
        if idle_ticks % 15 == 0:
            yield ": keep-alive\n\n"
        time.sleep(1)

"""Persistence, token validation and background analysis for collector uploads."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

from fastapi import HTTPException, UploadFile
from starlette.datastructures import Headers

from app.database import (
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


def _token_ttl_seconds() -> int:
    return max(60, int(os.getenv("COLLECTOR_TOKEN_TTL_SECONDS", "1800")))


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
        status="awaiting_upload",
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


def recover_interrupted_sessions() -> None:
    """Recover stale upload claims and terminate jobs lost during a restart."""

    now = local_database_time()
    with get_session_factory()() as db:
        uploading = db.query(CollectorSession).filter(
            CollectorSession.status == "uploading",
            CollectorSession.upload_consumed_at.is_(None),
        ).all()
        for record in uploading:
            record.status = "awaiting_upload" if record.token_expires_at >= now else "expired"
            record.updated_at = now
            if record.status == "expired":
                record.completed_at = now
        interrupted = db.query(CollectorSession).filter(
            CollectorSession.status.in_(["queued", "analyzing"])
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
                CollectorSession.status == "awaiting_upload",
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
        record.status = "awaiting_upload"
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
                    if event_type == "step":
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
                    elif event_type in {"error", "cancelled"}:
                        update_session(
                            session_id,
                            status="failed",
                            error_message=data,
                            event_type="failed",
                            event_payload={"message": data},
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

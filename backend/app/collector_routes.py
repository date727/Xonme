"""Cloud endpoints used by the browser and the Windows collector."""

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse

from app.auth import get_current_user
from app.collector_schemas import (
    CollectorSessionCreate,
    CollectorSessionCreated,
    CollectorSessionFinalize,
    CollectorSessionStatus,
)
from app.collector_service import (
    collector_session_snapshot,
    create_collector_session,
    finalize_collector_session,
    get_owned_collector_session,
    iter_session_events,
    save_collector_chunk,
    save_collector_upload,
)
from app.database import User
from app.model_config import get_model_config


router = APIRouter(prefix="/collector/sessions", tags=["collector"])


def _status(record) -> CollectorSessionStatus:
    return CollectorSessionStatus(**collector_session_snapshot(record))


def _bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="缺少上传令牌")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="缺少上传令牌")
    return token


@router.post("", response_model=CollectorSessionCreated, status_code=status.HTTP_201_CREATED)
def create_session(
    payload: CollectorSessionCreate,
    user: User = Depends(get_current_user),
) -> CollectorSessionCreated:
    model = get_model_config(payload.model_id)
    record, raw_token = create_collector_session(user, model.key)
    return CollectorSessionCreated(
        session_id=record.id,
        upload_token=raw_token,
        expires_at=record.token_expires_at,
        upload_path=f"/collector/sessions/{record.id}/chunks/{{sequence}}",
    )


@router.put("/{session_id}/chunks/{sequence}", status_code=status.HTTP_202_ACCEPTED)
def upload_chunk(
    session_id: str,
    sequence: int,
    pcap: UploadFile = File(...),
    authorization: str | None = Header(default=None),
    x_chunk_sha256: str | None = Header(default=None),
) -> dict:
    token = _bearer_token(authorization)
    chunk, duplicate, received_chunks, received_bytes = save_collector_chunk(
        session_id, token, sequence, pcap, x_chunk_sha256
    )
    return {
        "session_id": session_id,
        "sequence": chunk.sequence,
        "sha256": chunk.sha256,
        "accepted": True,
        "duplicate": duplicate,
        "received_chunks": received_chunks,
        "uploaded_bytes": received_bytes,
    }


@router.post("/{session_id}/finalize", status_code=status.HTTP_202_ACCEPTED)
def finalize_session(
    session_id: str,
    payload: CollectorSessionFinalize,
    authorization: str | None = Header(default=None),
) -> dict:
    record = finalize_collector_session(
        session_id,
        _bearer_token(authorization),
        total_chunks=payload.total_chunks,
        total_bytes=payload.total_bytes,
    )
    return {"session_id": record.id, "status": record.status}


@router.post("/{session_id}/pcap", status_code=status.HTTP_202_ACCEPTED)
def upload_pcap(
    session_id: str,
    pcap: UploadFile = File(...),
    authorization: str | None = Header(default=None),
    x_capture_sha256: str | None = Header(default=None),
) -> dict:
    record = save_collector_upload(
        session_id, _bearer_token(authorization), pcap, x_capture_sha256
    )
    return {"session_id": record.id, "status": record.status, "sha256": record.sha256}


@router.get("/{session_id}", response_model=CollectorSessionStatus)
def get_session(session_id: str, user: User = Depends(get_current_user)) -> CollectorSessionStatus:
    record = get_owned_collector_session(session_id, user.id)
    if not record:
        raise HTTPException(status_code=404, detail="采集会话不存在")
    return _status(record)


@router.get("/{session_id}/events")
def session_events(
    session_id: str,
    after: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
) -> StreamingResponse:
    if not get_owned_collector_session(session_id, user.id):
        raise HTTPException(status_code=404, detail="采集会话不存在")
    return StreamingResponse(
        iter_session_events(session_id, user.id, after),
        media_type="text/event-stream; charset=utf-8",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

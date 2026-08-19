"""Request and response models for browser-managed collector sessions."""

from datetime import datetime

from pydantic import BaseModel, Field


class CollectorSessionCreate(BaseModel):
    model_id: str | None = Field(default=None, max_length=80)


class CollectorSessionCreated(BaseModel):
    session_id: str
    upload_token: str
    expires_at: datetime
    upload_path: str


class CollectorSessionFinalize(BaseModel):
    total_chunks: int = Field(ge=1, le=10000)
    total_bytes: int = Field(ge=4)


class CollectorSessionStatus(BaseModel):
    session_id: str
    status: str
    current_step: str | None = None
    original_filename: str | None = None
    file_size: int | None = None
    sha256: str | None = None
    analysis_record_id: int | None = None
    error_message: str | None = None
    received_chunks: int = 0
    received_bytes: int = 0
    analyzed_bytes: int | None = None
    connection_count: int | None = None
    suspicious_count: int | None = None
    last_analyzed_at: datetime | None = None
    recent_alerts: list[dict] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None


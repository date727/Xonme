"""Local collector API models."""

from pydantic import BaseModel, Field


class CaptureStartRequest(BaseModel):
    interface_id: str = Field(min_length=1, max_length=64)
    capture_filter: str = Field(default="tcp or udp", max_length=512)
    max_duration_seconds: int = Field(default=60, ge=10, le=3600)
    max_file_size_mb: int = Field(default=100, ge=1, le=100)
    cloud_session_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    upload_token: str = Field(min_length=20, max_length=256)


class CaptureInterface(BaseModel):
    id: str
    name: str
    description: str
    display_name: str

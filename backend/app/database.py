"""SQLAlchemy persistence for C2Sherlock application data.

PCAP files and generated reports stay on disk (or an object store later).  This
module stores only their metadata, ownership and structured analysis result.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, JSON, String, Text, create_engine, func, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


def get_database_url() -> str | None:
    """Return the configured SQLAlchemy URL, without providing unsafe defaults."""

    return os.getenv("DATABASE_URL") or None


def local_database_time() -> datetime:
    """Return the server's current local time as a database-safe datetime."""

    return datetime.now().astimezone().replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


# SQLite auto-increments only an ``INTEGER PRIMARY KEY`` column. Keep BIGINT
# identifiers for MySQL while emitting INTEGER for SQLite databases.
PRIMARY_KEY_TYPE = BigInteger().with_variant(Integer(), "sqlite")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(PRIMARY_KEY_TYPE, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=local_database_time)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=local_database_time, onupdate=local_database_time
    )

    analyses: Mapped[list["AnalysisRecord"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    collector_sessions: Mapped[list["CollectorSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id: Mapped[int] = mapped_column(PRIMARY_KEY_TYPE, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        PRIMARY_KEY_TYPE, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)
    model_id: Mapped[str | None] = mapped_column(String(80))
    result_json: Mapped[dict | None] = mapped_column(JSON)
    report_markdown: Mapped[str | None] = mapped_column(Text)
    report_path: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=local_database_time)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    user: Mapped[User] = relationship(back_populates="analyses")


class CollectorSession(Base):
    """One browser-created upload slot used by the Windows collector."""

    __tablename__ = "collector_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[int] = mapped_column(
        PRIMARY_KEY_TYPE, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    upload_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    token_expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    upload_consumed_at: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="awaiting_upload", index=True)
    current_step: Mapped[str | None] = mapped_column(String(24))
    model_id: Mapped[str | None] = mapped_column(String(80))
    analysis_record_id: Mapped[int | None] = mapped_column(
        PRIMARY_KEY_TYPE, ForeignKey("analysis_records.id", ondelete="SET NULL"), index=True
    )
    original_filename: Mapped[str | None] = mapped_column(String(255))
    storage_path: Mapped[str | None] = mapped_column(Text)
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=local_database_time)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=local_database_time, onupdate=local_database_time
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    user: Mapped[User] = relationship(back_populates="collector_sessions")
    events: Mapped[list["CollectorEvent"]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="CollectorEvent.id"
    )


class CollectorEvent(Base):
    """Persisted SSE event so reconnecting browsers can resume progress."""

    __tablename__ = "collector_events"

    id: Mapped[int] = mapped_column(PRIMARY_KEY_TYPE, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("collector_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=local_database_time)

    session: Mapped[CollectorSession] = relationship(back_populates="events")


def create_database_engine():
    database_url = get_database_url()
    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured. Copy backend/.env.example to backend/.env first.")
    url = make_url(database_url)
    if url.drivername.startswith("sqlite"):
        if url.database and url.database != ":memory:":
            Path(url.database).expanduser().parent.mkdir(parents=True, exist_ok=True)
        return create_engine(
            database_url,
            connect_args={"check_same_thread": False},
        )
    return create_engine(database_url, pool_pre_ping=True)


def initialise_database() -> None:
    """Create missing application tables without altering existing data."""

    engine = create_database_engine()
    Base.metadata.create_all(engine)


def check_database_connection() -> bool:
    """Return whether the configured database is reachable."""

    try:
        with create_database_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def get_session_factory():
    return sessionmaker(bind=create_database_engine(), autoflush=False, autocommit=False)


def create_analysis_record(
    *,
    user_id: int,
    original_filename: str,
    storage_path: str,
    sha256: str,
    file_size: int,
    model_id: str | None,
) -> int:
    """Create a record for an authenticated user's in-progress analysis."""

    with get_session_factory()() as session:
        record = AnalysisRecord(
            user_id=user_id,
            original_filename=original_filename,
            storage_path=storage_path,
            sha256=sha256,
            file_size=file_size,
            model_id=model_id,
            status="processing",
        )
        session.add(record)
        session.commit()
        session.refresh(record)
        return record.id


def finish_analysis_record(
    record_id: int,
    *,
    status: str,
    result_json: dict | None = None,
    report_markdown: str | None = None,
    report_path: str | None = None,
) -> None:
    """Persist a final state without affecting anonymous analyses."""

    with get_session_factory()() as session:
        record = session.get(AnalysisRecord, record_id)
        if not record:
            return
        record.status = status
        record.result_json = result_json
        record.report_markdown = report_markdown
        record.report_path = report_path
        record.completed_at = local_database_time()
        session.commit()


def _record_to_dict(record: AnalysisRecord) -> dict:
    """Return only the task data that an API endpoint may expose to its owner."""

    return {
        "id": record.id,
        "original_filename": record.original_filename,
        "storage_path": record.storage_path,
        "file_size": record.file_size,
        "status": record.status,
        "result_json": record.result_json,
        "report_markdown": record.report_markdown,
        "created_at": record.created_at,
        "completed_at": record.completed_at,
    }


def list_analysis_records(
    user_id: int,
    *,
    keyword: str = "",
    page: int = 1,
    page_size: int = 10,
) -> tuple[list[dict], int]:
    """Return one user's paginated task list and its matching-record count."""

    normalized_keyword = keyword.strip()
    safe_page = max(1, page)
    safe_page_size = max(1, page_size)
    with get_session_factory()() as session:
        query = session.query(AnalysisRecord).filter(AnalysisRecord.user_id == user_id)
        if normalized_keyword:
            # ``contains(..., autoescape=True)`` keeps user-entered ``%`` and
            # ``_`` as literal filename characters rather than SQL wildcards.
            query = query.filter(
                func.lower(AnalysisRecord.original_filename).contains(
                    normalized_keyword.lower(), autoescape=True
                )
            )
        total = query.count()
        records = (
            query.order_by(AnalysisRecord.created_at.desc())
            .offset((safe_page - 1) * safe_page_size)
            .limit(safe_page_size)
            .all()
        )
        return [_record_to_dict(record) for record in records], total


def get_analysis_record_for_user(record_id: int, user_id: int) -> dict | None:
    """Return a task only when it belongs to the requesting user."""

    with get_session_factory()() as session:
        record = (
            session.query(AnalysisRecord)
            .filter(AnalysisRecord.id == record_id, AnalysisRecord.user_id == user_id)
            .one_or_none()
        )
        return _record_to_dict(record) if record else None


def delete_analysis_record_for_user(record_id: int, user_id: int) -> bool:
    """Delete one owned database record after its artifact directory is removed."""

    with get_session_factory()() as session:
        record = (
            session.query(AnalysisRecord)
            .filter(AnalysisRecord.id == record_id, AnalysisRecord.user_id == user_id)
            .one_or_none()
        )
        if not record:
            return False
        session.delete(record)
        session.commit()
        return True

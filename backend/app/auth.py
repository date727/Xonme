"""User registration, login and cookie-based session endpoints."""

from __future__ import annotations

import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from jwt import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import User, get_session_factory


router = APIRouter(prefix="/auth", tags=["authentication"])

COOKIE_NAME = "c2sherlock_session"
TOKEN_LIFETIME_HOURS = 12
JWT_SECRET_FILE = Path(__file__).resolve().parent.parent / ".jwt_secret"
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,50}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class RegisterRequest(BaseModel):
    username: str = Field(max_length=50)
    email: str = Field(max_length=255)
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)
    confirm_new_password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime


def _database_session():
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def _jwt_secret() -> str:
    """Load a configured secret or create one persistent server-local secret."""

    configured_secret = os.getenv("JWT_SECRET", "").strip()
    if configured_secret:
        if len(configured_secret) < 32:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="JWT_SECRET 至少需要 32 个字符",
            )
        return configured_secret

    try:
        existing_secret = JWT_SECRET_FILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        existing_secret = ""
    except OSError as exc:
        raise HTTPException(status_code=500, detail="无法读取服务器会话密钥") from exc

    if existing_secret:
        if len(existing_secret) < 32:
            raise HTTPException(status_code=500, detail="服务器会话密钥长度不足")
        return existing_secret

    generated_secret = secrets.token_urlsafe(48)
    try:
        # O_EXCL ensures concurrent workers do not overwrite a newly created key.
        descriptor = os.open(str(JWT_SECRET_FILE), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as secret_file:
            secret_file.write(f"{generated_secret}\n")
        try:
            os.chmod(JWT_SECRET_FILE, 0o600)
        except OSError:
            # Windows does not apply POSIX modes; filesystem access controls still apply.
            pass
        return generated_secret
    except FileExistsError:
        # Another worker created it between the read and write attempts.
        created_secret = JWT_SECRET_FILE.read_text(encoding="utf-8").strip()
        if len(created_secret) < 32:
            raise HTTPException(status_code=500, detail="服务器会话密钥长度不足")
        return created_secret
    except OSError as exc:
        raise HTTPException(status_code=500, detail="无法创建服务器会话密钥") from exc


def _cookie_is_secure() -> bool:
    return os.getenv("COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes"}


def initialise_session_secret() -> None:
    """Ensure the persistent secret exists when the API process starts."""

    _jwt_secret()


def _to_user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        created_at=user.created_at,
    )


def _validate_registration(payload: RegisterRequest) -> tuple[str, str]:
    username = payload.username.strip()
    email = payload.email.strip().lower()
    if not USERNAME_PATTERN.fullmatch(username):
        raise HTTPException(status_code=422, detail="用户名需为 3-50 位字母、数字或下划线")
    if not EMAIL_PATTERN.fullmatch(email):
        raise HTTPException(status_code=422, detail="请输入有效的邮箱地址")
    if payload.password != payload.confirm_password:
        raise HTTPException(status_code=422, detail="两次输入的密码不一致")
    return username, email


def _validate_new_password(password: str, confirmation: str) -> None:
    if password != confirmation:
        raise HTTPException(status_code=422, detail="两次输入的密码不一致")
    if len(password) < 8:
        raise HTTPException(status_code=422, detail="新密码至少需要 8 位")


def _create_access_token(user: User) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(hours=TOKEN_LIFETIME_HOURS)
    return jwt.encode(
        {"sub": str(user.id), "exp": expires_at},
        _jwt_secret(),
        algorithm="HS256",
    )


def _set_session_cookie(response: Response, user: User) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=_create_access_token(user),
        max_age=TOKEN_LIFETIME_HOURS * 60 * 60,
        httponly=True,
        secure=_cookie_is_secure(),
        samesite="lax",
        path="/",
    )


def _decode_session_user_id(session_token: str) -> int:
    payload = jwt.decode(session_token, _jwt_secret(), algorithms=["HS256"])
    return int(payload["sub"])


def _load_active_user(user_id: int) -> User | None:
    """Load a user only after a request has presented a valid session token."""

    with get_session_factory()() as db:
        user = db.get(User, user_id)
        if not user or not user.is_active:
            return None
        db.expunge(user)
        return user


def get_current_user(
    session_token: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> User:
    if not session_token:
        raise HTTPException(status_code=401, detail="请先登录")
    try:
        user_id = _decode_session_user_id(session_token)
    except (InvalidTokenError, KeyError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="登录状态已失效，请重新登录") from None
    user = _load_active_user(user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="登录状态已失效，请重新登录")
    return user


def get_optional_current_user(
    session_token: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> User | None:
    """Return a logged-in user when available without requiring a DB for guests."""

    if not session_token:
        return None
    try:
        user_id = _decode_session_user_id(session_token)
    except (InvalidTokenError, KeyError, TypeError, ValueError):
        return None
    return _load_active_user(user_id)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, response: Response, db: Session = Depends(_database_session)) -> UserResponse:
    username, email = _validate_registration(payload)
    existing = db.query(User).filter(or_(User.username == username, User.email == email)).first()
    if existing:
        field = "用户名" if existing.username == username else "邮箱"
        raise HTTPException(status_code=409, detail=f"该{field}已被使用")

    user = User(username=username, email=email, password_hash=password_context.hash(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    _set_session_cookie(response, user)
    return _to_user_response(user)


@router.post("/login", response_model=UserResponse)
def login(payload: LoginRequest, response: Response, db: Session = Depends(_database_session)) -> UserResponse:
    identifier = payload.identifier.strip()
    user = db.query(User).filter(or_(User.username == identifier, User.email == identifier.lower())).first()
    if not user or not user.is_active or not password_context.verify(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="用户名/邮箱或密码错误")
    _set_session_cookie(response, user)
    return _to_user_response(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


@router.get("/me", response_model=UserResponse)
def current_user(user: User = Depends(get_current_user)) -> UserResponse:
    return _to_user_response(user)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: ChangePasswordRequest,
    response: Response,
    user: User = Depends(get_current_user),
    db: Session = Depends(_database_session),
) -> None:
    _validate_new_password(payload.new_password, payload.confirm_new_password)
    stored_user = db.get(User, user.id)
    if not stored_user or not password_context.verify(payload.current_password, stored_user.password_hash):
        raise HTTPException(status_code=401, detail="当前密码不正确")
    stored_user.password_hash = password_context.hash(payload.new_password)
    db.commit()
    response.delete_cookie(COOKIE_NAME, path="/")

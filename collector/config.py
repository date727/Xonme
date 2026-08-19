"""Configuration for the Windows loopback collector."""

from __future__ import annotations

import os
import json
import sys
from dataclasses import dataclass
from pathlib import Path


def _default_data_dir() -> Path:
    root = os.getenv("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(root) / "C2Sherlock" / "Collector"


def _bundled_settings() -> dict:
    roots = []
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        roots.append(Path(bundle_root))
    roots.append(Path(__file__).resolve().parent)
    for root in roots:
        path = root / "config.json"
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


_SETTINGS = _bundled_settings()


def _setting(name: str, default):
    env_name = f"C2S_{name.upper()}"
    return os.getenv(env_name, _SETTINGS.get(name, default))


def user_settings_path() -> Path:
    """Return the writable per-user settings file used by the collector."""

    return _default_data_dir() / "settings.json"


def load_user_settings() -> dict:
    """Load non-sensitive settings selected on this Windows computer."""

    path = user_settings_path()
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def save_user_setting(name: str, value: str) -> None:
    """Atomically update one local setting without changing bundled policy."""

    path = user_settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    settings = load_user_settings()
    settings[name] = value
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(settings, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


@dataclass(frozen=True)
class CollectorConfig:
    host: str = "127.0.0.1"
    port: int = int(_setting("collector_port", 8766))
    cloud_api_base: str = str(_setting("cloud_api_base", "http://127.0.0.1:8765")).rstrip("/")
    allowed_origins: tuple[str, ...] = tuple(
        origin.strip()
        for origin in str(
            _setting("allowed_origins", "http://127.0.0.1:5500,http://localhost:5500")
        ).split(",")
        if origin.strip()
    )
    data_dir: Path = _default_data_dir()
    min_duration_seconds: int = 10
    max_duration_seconds: int = 3600
    max_file_size_mb: int = 100
    chunk_duration_seconds: int = max(10, int(_setting("chunk_duration_seconds", 60)))
    chunk_size_mb: int = max(1, int(_setting("chunk_size_mb", 16)))
    max_filter_length: int = 512
    upload_connect_timeout: int = 15
    upload_read_timeout: int = 300


CONFIG = CollectorConfig()

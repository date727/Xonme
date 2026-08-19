"""Executable entry point for C2Sherlock Collector."""

import multiprocessing
import os

import uvicorn

from api import app
from config import CONFIG
from dumpcap_manager import ensure_dumpcap_configured


class SingleInstance:
    """Hold a one-byte Windows file lock for the lifetime of the controller."""

    def __init__(self) -> None:
        self._file = None

    def acquire(self) -> bool:
        CONFIG.data_dir.mkdir(parents=True, exist_ok=True)
        self._file = (CONFIG.data_dir / "collector.lock").open("a+b")
        self._file.seek(0)
        if self._file.read(1) == b"":
            self._file.seek(0)
            self._file.write(b"0")
            self._file.flush()
        try:
            import msvcrt

            self._file.seek(0)
            msvcrt.locking(self._file.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except (ImportError, OSError):
            self._file.close()
            self._file = None
            return os.name != "nt"

    def release(self) -> None:
        if not self._file:
            return
        try:
            import msvcrt

            self._file.seek(0)
            msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
        except (ImportError, OSError):
            pass
        self._file.close()
        self._file = None


def main() -> None:
    instance = SingleInstance()
    if not instance.acquire():
        print("C2Sherlock Collector 已经在运行。")
        return
    try:
        ensure_dumpcap_configured()
        uvicorn.run(app, host=CONFIG.host, port=CONFIG.port, log_level="info")
    finally:
        instance.release()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()

"""Locate and safely control the dumpcap program installed with Wireshark."""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

from config import CONFIG
from models import CaptureInterface


INTERFACE_PATTERN = re.compile(r"^\s*(\d+)\.\s+(.+?)\s*$")


class DumpcapError(RuntimeError):
    pass


def find_dumpcap() -> Path | None:
    configured = os.getenv("C2S_DUMPCAP_PATH")
    candidates = [
        Path(configured) if configured else None,
        Path(os.getenv("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "dumpcap.exe",
        Path(os.getenv("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark" / "dumpcap.exe",
    ]
    located = shutil.which("dumpcap.exe")
    if located:
        candidates.append(Path(located))
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate.resolve()
    return None


def list_interfaces(dumpcap_path: Path) -> list[CaptureInterface]:
    try:
        result = subprocess.run(
            [str(dumpcap_path), "-D"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DumpcapError(f"无法执行 dumpcap：{exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise DumpcapError(detail or "dumpcap 无法枚举网卡，请检查 Npcap 和运行权限")
    interfaces: list[CaptureInterface] = []
    for raw_line in result.stdout.splitlines():
        match = INTERFACE_PATTERN.match(raw_line)
        if not match:
            continue
        interface_id, raw_value = match.groups()
        name = raw_value.strip()
        description = name
        if name.endswith(")") and " (" in name:
            name, description = name.rsplit(" (", 1)
            description = description[:-1].strip()
        display_name = _friendly_name(description, interface_id)
        interfaces.append(
            CaptureInterface(
                id=interface_id,
                name=name.strip(),
                description=description,
                display_name=display_name,
            )
        )
    if not interfaces:
        raise DumpcapError("dumpcap 未返回可用网卡")
    return interfaces


def probe_capture_access(dumpcap_path: Path, interface_id: str) -> None:
    """Open one interface just long enough to list its supported link types."""

    try:
        result = subprocess.run(
            [str(dumpcap_path), "-i", interface_id, "-L"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DumpcapError(f"无法验证网卡抓包权限：{exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise DumpcapError(detail or "无法打开网卡，请检查 Npcap 或以管理员身份运行控制器")


def _friendly_name(description: str, interface_id: str) -> str:
    lowered = description.lower()
    if "wi-fi" in lowered or "wireless" in lowered or "wlan" in lowered:
        return f"Wi-Fi（{description}）"
    if "ethernet" in lowered or "以太网" in lowered:
        return f"以太网（{description}）"
    return f"网卡 {interface_id}（{description}）"


def validate_capture_filter(dumpcap_path: Path, capture_filter: str) -> str:
    del dumpcap_path  # dumpcap performs the authoritative compile at capture start.
    normalized = capture_filter.strip()
    if not normalized:
        return "tcp or udp"
    if len(normalized) > CONFIG.max_filter_length or "\x00" in normalized:
        raise DumpcapError("抓包过滤规则长度或内容无效")
    return normalized


def start_dumpcap(
    dumpcap_path: Path,
    interface_id: str,
    capture_filter: str,
    duration_seconds: int,
    max_file_size_mb: int,
    output_path: Path,
) -> subprocess.Popen:
    output_path.parent.mkdir(parents=True, exist_ok=False)
    # A distinct process group lets Windows deliver CTRL_BREAK to dumpcap so it
    # can flush and close PCAPNG normally. CREATE_NO_WINDOW would prevent this.
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    log_path = output_path.parent / "dumpcap.log"
    command = [
        str(dumpcap_path),
        "-i", interface_id,
        "-f", capture_filter,
        "-a", f"duration:{duration_seconds}",
        "-a", f"filesize:{max_file_size_mb * 1024}",
        "-w", str(output_path),
    ]
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=log_file,
            creationflags=flags,
        )
    time.sleep(0.8)
    if process.poll() is not None:
        detail = log_path.read_text(encoding="utf-8", errors="replace").strip()
        raise DumpcapError(detail or "dumpcap 启动失败")
    return process


def stop_dumpcap(process: subprocess.Popen, timeout: float = 12.0) -> None:
    if process.poll() is not None:
        return
    try:
        process.send_signal(signal.CTRL_BREAK_EVENT)
        process.wait(timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

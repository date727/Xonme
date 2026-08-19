"""Locate and safely control the dumpcap program installed with Wireshark."""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

from config import CONFIG, load_user_settings, save_user_setting
from models import CaptureInterface


INTERFACE_PATTERN = re.compile(r"^\s*(\d+)\.\s+(.+?)\s*$")


class DumpcapError(RuntimeError):
    pass


def _resolve_dumpcap_path(value: str | os.PathLike | None) -> Path | None:
    """Resolve a file or installation directory to a real dumpcap executable."""

    if not value:
        return None
    candidate = Path(os.path.expandvars(str(value))).expanduser()
    if candidate.is_dir():
        candidate = candidate / "dumpcap.exe"
    if not candidate.is_file() or candidate.name.lower() != "dumpcap.exe":
        return None
    return candidate.resolve()


def find_dumpcap() -> Path | None:
    user_configured = load_user_settings().get("dumpcap_path")
    candidates = [
        os.getenv("C2S_DUMPCAP_PATH"),
        user_configured if isinstance(user_configured, str) else None,
        Path(os.getenv("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "dumpcap.exe",
        Path(os.getenv("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark" / "dumpcap.exe",
    ]
    located = shutil.which("dumpcap.exe")
    if located:
        candidates.append(located)
    for candidate in candidates:
        resolved = _resolve_dumpcap_path(candidate)
        if resolved:
            return resolved
    return None


def validate_dumpcap_executable(path: Path) -> Path:
    """Verify that a selected file is dumpcap and can be executed safely."""

    resolved = _resolve_dumpcap_path(path)
    if not resolved:
        raise DumpcapError("请选择 Wireshark 安装目录中的 dumpcap.exe")
    try:
        result = subprocess.run(
            [str(resolved), "-v"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DumpcapError(f"无法执行所选 dumpcap.exe：{exc}") from exc
    version_text = f"{result.stdout}\n{result.stderr}".lower()
    if result.returncode != 0 or "dumpcap" not in version_text:
        detail = (result.stderr or result.stdout or "").strip()
        raise DumpcapError(detail or "所选文件不是可用的 dumpcap.exe")
    return resolved


def prompt_for_dumpcap() -> Path | None:
    """Ask for dumpcap in the launch terminal and remember a valid path."""

    if os.name != "nt":
        return None
    print("\n未自动找到 Wireshark dumpcap.exe。")
    print("请输入 dumpcap.exe 的完整路径。")
    print("也可以输入 Wireshark 安装目录，程序会自动查找其中的 dumpcap.exe。")
    print(r"示例：C:\Program Files\Wireshark\dumpcap.exe")
    print("直接按回车可暂时跳过，之后重启 Collector 可重新输入。")
    while True:
        try:
            selected = input("dumpcap 路径> ").strip().strip('"').strip("'")
        except (EOFError, KeyboardInterrupt):
            print("\n未配置 dumpcap 路径。")
            return None
        if not selected:
            print("未配置 dumpcap 路径，Collector 将继续启动，但暂时不能抓包。")
            return None
        try:
            resolved = validate_dumpcap_executable(Path(selected))
            save_user_setting("dumpcap_path", str(resolved))
            print(f"dumpcap 路径已验证并保存：{resolved}")
            return resolved
        except (DumpcapError, OSError) as exc:
            print(f"路径无效：{exc}")
            print("请重新输入，或直接按回车跳过。")


def ensure_dumpcap_configured() -> Path | None:
    """Use automatic discovery first, then ask in the launch terminal."""

    return find_dumpcap() or prompt_for_dumpcap()


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
        "-b", f"duration:{CONFIG.chunk_duration_seconds}",
        "-b", f"filesize:{min(CONFIG.chunk_size_mb, max_file_size_mb) * 1024}",
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

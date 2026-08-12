import json
import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

# Ensure backend/ is on sys.path so `from app.xxx` imports work
# regardless of whether uvicorn is started from project root or backend/
_sys_path_root = Path(__file__).resolve().parent.parent  # backend/
if str(_sys_path_root) not in sys.path:
    sys.path.insert(0, str(_sys_path_root))

from app.model_config import (
    DEFAULT_MODEL_KEY,
    ModelConfig,
    get_chat_completions_url,
    get_model_config,
    public_model_options,
)
from app.database import (
    User,
    check_database_connection,
    create_analysis_record,
    delete_analysis_record_for_user,
    finish_analysis_record,
    get_analysis_record_for_user,
    list_analysis_records,
)
from app.auth import (
    get_current_user,
    get_optional_current_user,
    initialise_session_secret,
    router as auth_router,
)

# LSTM beacon detection - gracefully degrades if dependencies are missing
try:
    from app.lstm_predictor import predict_beacons, format_for_prompt as _fmt_lstm

    _LSTM_AVAILABLE = True
except ImportError:
    _LSTM_AVAILABLE = False

# RAG engine - core pipeline (Zeek -> RITA -> RAG -> AI)
try:
    from app.rag_engine import ThreatAttributionEngine
    from app.data_extractor import ThreatFeatureExtractor

    _RAG_AVAILABLE = True
except ImportError as exc:
    print(f"RAG disabled - import failed: {exc}")
    _RAG_AVAILABLE = False

load_dotenv()

APP_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = APP_ROOT / "data"
USER_RUNS_DIR = DATA_DIR / "analysis_runs" / "users"
GUEST_JOBS_DIR = DATA_DIR / "guest_jobs"
ARTIFACT_SCHEMA_VERSION = 1

app = FastAPI()
app.include_router(auth_router)


@app.on_event("startup")
async def initialise_auth_secret() -> None:
    initialise_session_secret()

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=os.getenv(
        "CORS_ORIGIN_REGEX", r"^https?://(localhost|127[.]0[.]0[.]1)(:[0-9]+)?$"
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeResponse(BaseModel):
    name: str
    csv_path: str
    analysis_markdown: str


class ReportExportRequest(BaseModel):
    markdown: str
    filename: str = "c2sherlock-report"


@app.get("/database/status")
async def database_status() -> dict[str, bool]:
    """Provide a lightweight health check for the application database."""

    return {"connected": check_database_connection()}


@app.get("/models")
async def list_report_models() -> dict:
    """Expose only safe model-picker metadata to the browser."""
    return {
        "default_model": DEFAULT_MODEL_KEY,
        "models": public_model_options(),
    }


@app.post("/reports/{report_format}")
async def export_report(report_format: str, payload: ReportExportRequest) -> Response:
    """Export the currently rendered report without storing a second copy."""
    if report_format not in {"docx", "pdf"}:
        raise HTTPException(status_code=404, detail="Unsupported report format")
    from app.report_export import build_docx, build_pdf

    content = build_docx(payload.markdown) if report_format == "docx" else build_pdf(payload.markdown)
    media_type = (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if report_format == "docx" else "application/pdf"
    )
    safe_name = _safe_path_component(Path(payload.filename).stem, "c2sherlock-report")
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{safe_name}.{report_format}"'},
    )


class AnalysisCancelled(Exception):
    """Raised when a client explicitly stops an in-progress analysis."""


@dataclass
class AnalysisJob:
    cancel_event: threading.Event = field(default_factory=threading.Event)
    processes: set[subprocess.Popen] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)


ACTIVE_ANALYSES: dict[str, AnalysisJob] = {}
ACTIVE_ANALYSES_LOCK = threading.Lock()
PENDING_CANCELLATIONS: dict[str, float] = {}
PENDING_CANCELLATION_TTL_SECONDS = 300


def _prune_pending_cancellations() -> None:
    cutoff = time.monotonic() - PENDING_CANCELLATION_TTL_SECONDS
    stale_ids = [analysis_id for analysis_id, created_at in PENDING_CANCELLATIONS.items() if created_at < cutoff]
    for analysis_id in stale_ids:
        PENDING_CANCELLATIONS.pop(analysis_id, None)


def ensure_dirs() -> None:
    USER_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    GUEST_JOBS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class AnalysisArtifacts:
    """All files produced by one analysis, kept under one task directory."""

    analysis_uuid: str
    display_name: str
    is_guest: bool
    root: Path
    input_path: Path
    zeek_dir: Path
    rita_dir: Path
    lstm_dir: Path
    merged_dir: Path
    rag_dir: Path
    report_dir: Path
    visualization_dir: Path

    @property
    def manifest_path(self) -> Path:
        return self.root / "manifest.json"

    @property
    def runtime_log_path(self) -> Path:
        return self.root / "runtime.log"


def _safe_path_component(value: str, fallback: str) -> str:
    """Keep human-readable names while preventing a filename from changing paths."""

    cleaned = re.sub(r"[^0-9A-Za-z_\-\u4e00-\u9fff]+", "_", value.strip())
    return cleaned.strip("._-")[:80] or fallback


def _allocate_artifacts(original_filename: str | None, user: User | None) -> AnalysisArtifacts:
    """Create the task directory before processing so every artifact has one home."""

    ensure_dirs()
    original_name = Path(original_filename or "upload.pcap").name
    safe_stem = _safe_path_component(Path(original_name).stem, "upload")
    suffix = Path(original_name).suffix.lower() or ".pcap"

    for _ in range(10):
        analysis_uuid = uuid.uuid4().hex
        if user:
            timestamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
            display_name = f"{timestamp}_{safe_stem}_{analysis_uuid[:8]}"
            root = USER_RUNS_DIR / _safe_path_component(user.username, "user") / display_name
        else:
            display_name = analysis_uuid
            root = GUEST_JOBS_DIR / analysis_uuid
        try:
            root.mkdir(parents=True, exist_ok=False)
            break
        except FileExistsError:
            continue
    else:
        raise RuntimeError("Unable to allocate analysis artifact directory")

    paths = {
        "input_path": root / "input" / f"{safe_stem}{suffix}",
        "zeek_dir": root / "zeek",
        "rita_dir": root / "rita",
        "lstm_dir": root / "lstm",
        "merged_dir": root / "merged",
        "rag_dir": root / "rag",
        "report_dir": root / "report",
        "visualization_dir": root / "visualization",
    }
    for path in paths.values():
        (path.parent if path.suffix else path).mkdir(parents=True, exist_ok=True)
    return AnalysisArtifacts(
        analysis_uuid=analysis_uuid,
        display_name=display_name,
        is_guest=user is None,
        root=root,
        **paths,
    )


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _append_runtime_log(artifacts: AnalysisArtifacts, message: str) -> None:
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    with artifacts.runtime_log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(f"[{timestamp}] {message}\n")


def _write_manifest(
    artifacts: AnalysisArtifacts,
    *,
    status: str,
    original_filename: str,
    user: User | None,
    rita_db_name: str,
    model_config: ModelConfig,
    sha256: str | None = None,
    file_size: int | None = None,
    error: str | None = None,
) -> None:
    _write_json(
        artifacts.manifest_path,
        {
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "analysis_uuid": artifacts.analysis_uuid,
            "display_name": artifacts.display_name,
            "owner_type": "guest" if artifacts.is_guest else "user",
            "username": user.username if user else None,
            "original_filename": original_filename,
            "sha256": sha256,
            "file_size": file_size,
            "status": status,
            "rita_database": rita_db_name,
            "models": {
                "report": model_config.key,
                "lstm": "lstm_beacon_detector" if _LSTM_AVAILABLE else None,
                "rag": "mitre_attack_chroma" if _RAG_AVAILABLE else None,
            },
            "artifacts": {
                "input": "input/",
                "zeek": "zeek/",
                "rita": "rita/",
                "lstm": "lstm/",
                "merged": "merged/threats.json",
                "rag": "rag/",
                "report": "report/analysis.md",
                "visualization": "visualization/dashboard.json",
            },
            "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "error": error,
        },
    )


def _set_manifest_status(artifacts: AnalysisArtifacts, status: str, error: str | None = None) -> None:
    """Update terminal state without losing the upload metadata already recorded."""

    try:
        manifest = json.loads(artifacts.manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        manifest = {"schema_version": ARTIFACT_SCHEMA_VERSION, "analysis_uuid": artifacts.analysis_uuid}
    manifest["status"] = status
    manifest["error"] = error
    manifest["updated_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
    _write_json(artifacts.manifest_path, manifest)


def make_rita_db_name(run_id: str) -> str:
    """Build a RITA-safe database name.

    RITA v5 rejects some raw UUID hex names such as names that start
    with a digit. Prefix with a letter to keep names deterministic and valid.
    """

    return f"run_{run_id}"


def _collect_zeek_logs(log_dir: Path) -> str:
    """Read all Zeek TSV log files and return them as a single text blob."""

    parts: list[str] = []
    for log_path in sorted(log_dir.glob("*.log")):
        try:
            content = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Strip Zeek header lines that add parser noise, but keep #fields and
        # #types so the LLM can still understand the column layout.
        lines = content.splitlines()
        filtered = [ln for ln in lines if not ln.startswith("#separator")]
        parts.append(f"=== {log_path.name} ===\n" + "\n".join(filtered))

    return "\n\n".join(parts) if parts else "(No Zeek logs found)"


def _save_uploaded_pcap(upload: UploadFile, destination: Path, job: AnalysisJob | None = None) -> None:
    """Copy an upload in chunks so cancellation also works during large uploads."""

    with destination.open("wb") as file_obj:
        while chunk := upload.file.read(1024 * 1024):
            _raise_if_cancelled(job)
            file_obj.write(chunk)
    _raise_if_cancelled(job)


def _raise_if_cancelled(job: AnalysisJob | None) -> None:
    if job and job.cancel_event.is_set():
        raise AnalysisCancelled()


def _terminate_process(process: subprocess.Popen) -> None:
    """Stop a command and, on Windows, any child commands it spawned."""

    if process.poll() is not None:
        return

    if os.name == "nt":
        # Zeek/RITA may create child processes. /T avoids leaving them behind.
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            text=True,
            check=False,
        )
    else:
        os.killpg(process.pid, signal.SIGTERM)


def _cancel_job(job: AnalysisJob) -> None:
    job.cancel_event.set()
    with job.lock:
        processes = list(job.processes)
    for process in processes:
        _terminate_process(process)


def run_command(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int | None = None,
    *,
    job: AnalysisJob | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a cancellable subprocess, raising HTTPException on failure/timeout."""

    _raise_if_cancelled(job)
    popen_kwargs: dict = {
        "cwd": cwd,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(cmd, **popen_kwargs)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start command: {' '.join(cmd)}") from exc

    if job:
        with job.lock:
            job.processes.add(process)

    started_at = time.monotonic()
    stdout = ""
    stderr = ""
    try:
        while True:
            try:
                # communicate() drains stdout/stderr while waiting. Polling alone can
                # deadlock when a child command writes enough output to fill a pipe.
                stdout, stderr = process.communicate(timeout=0.15)
                break
            except subprocess.TimeoutExpired:
                if job and job.cancel_event.is_set():
                    _terminate_process(process)
                    try:
                        process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
                    raise AnalysisCancelled()
                if timeout is not None and time.monotonic() - started_at >= timeout:
                    _terminate_process(process)
                    try:
                        process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
                    raise HTTPException(
                        status_code=500,
                        detail=f"Command timed out after {timeout}s: {' '.join(cmd)}",
                    )
    finally:
        if job:
            with job.lock:
                job.processes.discard(process)

    if process.returncode != 0:
        detail = (stderr or "").strip() or (stdout or "").strip() or "Command failed"
        raise HTTPException(status_code=500, detail=detail)

    return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)


def run_zeek(pcap_path: str, output_dir: Path, *, job: AnalysisJob | None = None) -> None:
    """Run Zeek on a PCAP file, trying standard CLI first, then readpcap."""

    try:
        run_command(
            ["zeek", "-r", pcap_path, "-C", "LogAscii::use_json=F"],
            cwd=output_dir,
            job=job,
        )
        return
    except HTTPException:
        pass

    run_command(["zeek", "readpcap", pcap_path, str(output_dir)], job=job)


def _build_sample_rag_context(
    rag_engine: "ThreatAttributionEngine",
    merged_features: list[dict],
    *,
    job: AnalysisJob | None = None,
) -> tuple[str, list[dict]]:
    """Run attribution for every suspicious connection without changing dashboard shape."""

    results: list[dict] = []
    sections = ["## 全量可疑连接与 RAG 检索证据"]
    for index, feature in enumerate(merged_features, 1):
        _raise_if_cancelled(job)
        endpoint = (
            f"{feature.get('src_ip') or '-'} → "
            f"{feature.get('dst_ip') or '-'}:{feature.get('dst_port') or '-'}"
        )
        sources = feature.get("detection_sources") or []
        if isinstance(sources, str):
            sources = [item for item in sources.split(";") if item]
        try:
            result = rag_engine.attribute_single_threat(feature)
            results.append(result)
            report = rag_engine.generate_attribution_report(result)
            sections.append(
                f"\n### 可疑连接 {index}\n"
                f"- **连接**：{endpoint}\n"
                f"- **检测来源**：{' + '.join(sources) if sources else '未知'}\n\n"
                f"{report}"
            )
        except AnalysisCancelled:
            raise
        except Exception as exc:
            print(f"RAG: retrieval failed for threat {index}/{len(merged_features)} - {exc}")
            sections.append(
                f"\n### 可疑连接 {index}\n"
                f"- **连接**：{endpoint}\n"
                "- **RAG 状态**：该连接检索失败，检测证据仍予保留。"
            )
    return "\n".join(sections), results


def _rag_evidence_appendix(rag_context: str | None) -> str:
    return f"\n\n---\n\n{rag_context}" if rag_context else ""


def _lstm_evidence_appendix(lstm_results: dict | None) -> str:
    return f"\n\n---\n\n{_fmt_lstm(lstm_results)}"


def _build_ai_request(
    csv_text: str,
    lstm_results: dict | None = None,
    *,
    model_config: ModelConfig,
    rita_ok: bool = True,
    rag_context: str | None = None,
    stream: bool = False,
) -> tuple[str, dict[str, str], dict]:
    url = get_chat_completions_url(model_config)
    headers = {
        "Authorization": f"Bearer {model_config.api_key}",
        "Content-Type": "application/json",
    }

    source = "RITA CSV report" if rita_ok else "Zeek network log data"
    system_prompt = (
        "你是一名资深网络威胁分析师。"
        "请始终使用中文回答，并输出专业的 Markdown 报告。"
    )
    prompt = (
        "请输出一份中文 Markdown 报告，且第一行标题必须严格为："
        "# C2Sherlock AI分析报告\n\n"
        f"请分析以下{source}，并按下面结构组织内容：\n"
        "1. **执行摘要** - 用 2-3 句话概括核心发现\n"
        "2. **主要威胁特征** - 说明可疑 C2 行为、Beacon 特征、异常现象\n"
        "3. **风险评估** - 说明严重性、潜在影响与业务风险\n"
        "4. **处置建议** - 给出面向 SOC 团队的具体下一步措施\n\n"
    )
    
    if rag_context:
        prompt += (
            "\n以下是 ATT&CK 溯源上下文，请用于丰富分析：\n"
            f"{rag_context}\n\n"
            "请在报告中新增第 5 节“威胁归因”，至少包括：\n"
            "- 最可能的 APT 组织或组织集合\n"
            "- 对应的 MITRE ATT&CK 技术编号\n"
            "- 你的置信度与需要保留的 caveat\n"
        )

    lstm_markdown = _fmt_lstm(lstm_results)
    prompt += (
        "\n以下是系统生成的 LSTM 时序检测结果。无论是否命中 C2，"
        "请在报告中明确说明该检测结论；未命中不代表绝对安全：\n"
        f"{lstm_markdown}\n"
    )

    prompt += f"\n原始分析输入如下：\n{csv_text}"

    payload = {
        "model": model_config.model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        #"enable_thinking": False,
    }
    payload.update(model_config.request_options)
    if stream:
        payload["stream"] = True

    return url, headers, payload


def generate_ai_analysis(
    csv_text: str,
    lstm_results: dict | None = None,
    *,
    model_config: ModelConfig,
    rita_ok: bool = True,
    rag_context: str | None = None,
) -> str:
    url, headers, payload = _build_ai_request(
        csv_text,
        lstm_results=lstm_results,
        model_config=model_config,
        rita_ok=rita_ok,
        rag_context=rag_context,
        stream=False,
    )

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=120)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"{model_config.provider} API request failed") from exc

    data = response.json()
    try:
        report = data["choices"][0]["message"]["content"].strip()
        return report + _lstm_evidence_appendix(lstm_results) + _rag_evidence_appendix(rag_context)
    except (KeyError, IndexError, AttributeError) as exc:
        raise HTTPException(
            status_code=502, detail="Unexpected SiliconFlow response format"
        ) from exc


def stream_ai_analysis(
    csv_text: str,
    lstm_results: dict | None = None,
    *,
    model_config: ModelConfig,
    rita_ok: bool = True,
    rag_context: str | None = None,
    job: AnalysisJob | None = None,
):
    _raise_if_cancelled(job)
    if model_config.provider == "OpenAI":
        _, headers, chat_payload = _build_ai_request(
            csv_text,
            lstm_results=lstm_results,
            model_config=model_config,
            rita_ok=rita_ok,
            rag_context=rag_context,
            stream=False,
        )
        response_payload = {
            "model": model_config.model,
            "input": chat_payload["messages"],
            "stream": True,
            **model_config.request_options,
        }
        try:
            response = requests.post(
                f"{model_config.base_url.rstrip('/')}/responses",
                headers=headers,
                json=response_payload,
                timeout=120,
                stream=True,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail="OpenAI API request failed") from exc

        try:
            response.encoding = "utf-8"
            for raw_line in response.iter_lines(decode_unicode=False):
                _raise_if_cancelled(job)
                if not raw_line:
                    continue
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                try:
                    event = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
                if event.get("type") == "response.output_text.delta" and event.get("delta"):
                    yield event["delta"]
                elif event.get("type") == "response.failed":
                    raise HTTPException(status_code=502, detail="OpenAI report generation failed")
        finally:
            response.close()
        return

    url, headers, payload = _build_ai_request(
        csv_text,
        lstm_results=lstm_results,
        model_config=model_config,
        rita_ok=rita_ok,
        rag_context=rag_context,
        stream=True,
    )

    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=120,
            stream=True,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"{model_config.provider} API request failed") from exc

    try:
        response.encoding = "utf-8"
        for raw_line in response.iter_lines(chunk_size=1, decode_unicode=False):
            _raise_if_cancelled(job)
            if not raw_line:
                continue

            try:
                line = raw_line.decode("utf-8").strip()
            except UnicodeDecodeError:
                line = raw_line.decode("utf-8", errors="replace").strip()
            if not line.startswith("data:"):
                continue

            data = line[5:].strip()
            if data == "[DONE]":
                break

            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue

            choices = chunk.get("choices") or []

            # 某些兼容 API 会发送 choices=[] 的状态或用量分块，
            # 这种分块不包含正文，直接跳过即可。
            if not choices:
                continue

            choice = choices[0] or {}
            delta_obj = choice.get("delta") or {}

            delta = (
                delta_obj.get("content")
                or ""
            )

            if delta:
                yield delta
            # choice = chunk.get("choices", [{}])[0]
            # delta_obj = choice.get("delta", {})
            # delta = delta_obj.get("content") or delta_obj.get("reasoning_content") or ""
            # if delta:
            #     yield delta
    finally:
        response.close()


def _file_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cleanup_guest_artifacts(artifacts: AnalysisArtifacts | None) -> None:
    """Remove transient files after an anonymous analysis has been streamed."""

    if not artifacts or not artifacts.is_guest:
        return
    try:
        artifacts.root.relative_to(GUEST_JOBS_DIR)
    except ValueError:
        return
    shutil.rmtree(artifacts.root, ignore_errors=True)


def _owned_task_root(record: dict, user: User) -> Path:
    """Resolve a saved task directory and reject paths outside this user's area."""

    root = Path(record["storage_path"]).resolve()
    owner_root = (USER_RUNS_DIR / _safe_path_component(user.username, "user")).resolve()
    try:
        root.relative_to(owner_root)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="任务使用的是不受支持的旧存储路径") from exc
    if root.parent != owner_root:
        raise HTTPException(status_code=409, detail="任务目录结构无效，无法执行该操作")
    return root


def _task_conclusion(record: dict) -> dict[str, str]:
    """Keep processing state distinct from the actual security conclusion."""

    status = record["status"]
    if status != "completed":
        labels = {
            "processing": "分析中",
            "failed": "分析失败",
            "cancelled": "已取消",
        }
        return {"kind": status, "label": labels.get(status, "未完成")}
    dashboard = record.get("result_json") or {}
    threats = dashboard.get("threats") if isinstance(dashboard, dict) else None
    if isinstance(threats, list) and threats:
        return {"kind": "suspicious", "label": "发现可疑 C2 行为"}
    return {"kind": "normal", "label": "未发现可疑 C2 行为"}


def _delete_rita_database(database_name: str) -> None:
    """Delete only the generated RITA database for one confirmed task."""

    if not re.fullmatch(r"run_[0-9a-f]{32}", database_name):
        raise HTTPException(status_code=409, detail="RITA 数据库标识无效，已取消删除")
    try:
        result = subprocess.run(
            ["rita", "delete", database_name],
            input="y\n",
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail="RITA 不可用，未删除任务数据") from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="清理 RITA 数据库超时，未删除任务数据") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise HTTPException(status_code=500, detail=f"清理 RITA 数据库失败：{detail or '未知错误'}")


@app.get("/analyses")
async def list_saved_analyses(user: User = Depends(get_current_user)) -> dict:
    """List only the current user's persisted analysis tasks."""

    records = list_analysis_records(user.id)
    return {
        "analyses": [
            {
                "id": record["id"],
                "original_filename": record["original_filename"],
                "file_size": record["file_size"],
                "status": record["status"],
                "created_at": record["created_at"],
                "completed_at": record["completed_at"],
                "conclusion": _task_conclusion(record),
            }
            for record in records
        ]
    }


@app.get("/analyses/{record_id}/dashboard")
async def get_saved_analysis_dashboard(
    record_id: int, user: User = Depends(get_current_user)
) -> dict:
    """Load the structured dashboard for one owned, completed analysis."""

    record = get_analysis_record_for_user(record_id, user.id)
    if not record:
        raise HTTPException(status_code=404, detail="未找到该分析任务")
    if record["status"] != "completed":
        raise HTTPException(status_code=409, detail="该任务尚未成功完成，暂无详细数据")
    root = _owned_task_root(record, user)
    dashboard_path = root / "visualization" / "dashboard.json"
    try:
        dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="该任务的可视化数据不存在") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="读取任务可视化数据失败") from exc
    return {
        "analysis": {
            "id": record["id"],
            "original_filename": record["original_filename"],
            "file_size": record["file_size"],
            "status": record["status"],
            "created_at": record["created_at"],
            "completed_at": record["completed_at"],
            "report_markdown": record.get("report_markdown") or "",
        },
        "dashboard": dashboard,
    }


@app.delete("/analyses/{record_id}")
async def delete_saved_analysis(record_id: int, user: User = Depends(get_current_user)) -> dict:
    """Delete one owned task's RITA database, artifact directory, and DB record."""

    record = get_analysis_record_for_user(record_id, user.id)
    if not record:
        raise HTTPException(status_code=404, detail="未找到该分析任务")
    if record["status"] == "processing":
        raise HTTPException(status_code=409, detail="分析任务仍在运行，暂时不能删除")

    root = _owned_task_root(record, user)
    rita_metadata_path = root / "rita" / "metadata.json"
    rita_metadata: dict = {}
    try:
        rita_metadata = json.loads(rita_metadata_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        pass
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="读取 RITA 任务元数据失败") from exc

    if rita_metadata.get("imported") or rita_metadata.get("available"):
        _delete_rita_database(str(rita_metadata.get("database", "")))
    try:
        shutil.rmtree(root)
    except OSError as exc:
        raise HTTPException(status_code=500, detail="删除任务目录失败，数据库记录已保留") from exc
    if not delete_analysis_record_for_user(record_id, user.id):
        raise HTTPException(status_code=500, detail="任务目录已删除，但数据库记录删除失败")
    return {"deleted": True, "id": record_id}


def sse_event(event: str, data: str) -> str:
    return f"event: {event}\ndata: {data}\n\n"


@app.delete("/analyze/{analysis_id}")
async def cancel_analysis(analysis_id: str) -> dict[str, str]:
    """Request cancellation for one streaming analysis task."""

    with ACTIVE_ANALYSES_LOCK:
        _prune_pending_cancellations()
        job = ACTIVE_ANALYSES.get(analysis_id)
        if not job:
            # The multipart upload may still be arriving, so the streaming route
            # has not registered its job yet. Remember this cancellation request.
            PENDING_CANCELLATIONS[analysis_id] = time.monotonic()

    if job:
        _cancel_job(job)
    return {"status": "cancelling", "analysis_id": analysis_id}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_pcap(pcap: UploadFile = File(...)) -> AnalyzeResponse:
    artifacts = _allocate_artifacts(pcap.filename, None)
    name = artifacts.analysis_uuid
    rita_db_name = make_rita_db_name(name)
    upload_path = artifacts.input_path
    output_dir = artifacts.zeek_dir

    with upload_path.open("wb") as file_obj:
        shutil.copyfileobj(pcap.file, file_obj)

    run_zeek(str(upload_path), output_dir)

    zeek_logs = list(output_dir.glob("*.log"))
    if not zeek_logs:
        raise HTTPException(status_code=500, detail="Zeek did not produce any log files")

    rita_ok = False
    csv_text = ""

    try:
        print(f"RITA: importing logs from {output_dir} ...")
        run_command(
            ["rita", "import", f"--database={rita_db_name}", f"--logs={output_dir}"],
            timeout=600,
        )
        print("RITA: import OK")
    except HTTPException as exc:
        print(f"RITA: import failed - {exc.detail}")
    else:
        try:
            print(f"RITA: exporting view for db={rita_db_name} ...")
            view_result = subprocess.run(
                ["rita", "view", "--stdout", rita_db_name],
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            csv_text = view_result.stdout
            rita_ok = True
            print(f"RITA: view OK ({len(csv_text)} chars)")
        except subprocess.TimeoutExpired:
            print("RITA: view timed out after 120s")
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "").strip()
            print(f"RITA: view failed - {detail}")

    if not rita_ok:
        csv_text = _collect_zeek_logs(output_dir)
        print(f"RITA: falling back to raw Zeek logs ({len(csv_text)} chars)")

    csv_path = artifacts.rita_dir / "view.csv"
    if rita_ok:
        csv_path.write_text(csv_text, encoding="utf-8")

    # The new 24-dimensional model consumes reconstructed TCP connections.
    # DNS/UDP traffic remains on the RITA/RAG path.
    lstm_results = None
    if _LSTM_AVAILABLE:
        try:
            from app.pcap_lstm_feature_extractor import export_lstm_features_from_pcap

            print("LSTM: extracting all-TCP connection features from PCAP packet timestamps")
            lstm_csv_text = export_lstm_features_from_pcap(upload_path)

            if lstm_csv_text:
                print("LSTM: feature extraction complete, running beacon detection...")
                lstm_results = predict_beacons(lstm_csv_text)
            else:
                print("LSTM: skipped (no usable TCP connection sequence found in PCAP)")
        except Exception as exc:
            print(f"LSTM: analysis failed - {exc}")
            import traceback

            traceback.print_exc()

    # RAG attribution uses merged RITA and LSTM features when available.
    rag_context = None
    if not _RAG_AVAILABLE:
        print("RAG: skipped (dependencies not installed)")
    else:
        try:
            if (lstm_results and lstm_results.get("total_flagged", 0) > 0) or rita_ok:
                from app.threat_feature_merger import merge_threat_features

                rita_features = []
                if rita_ok:
                    print("RAG: extracting RITA threat features...")
                    extractor = ThreatFeatureExtractor(csv_text)
                    rita_features = extractor.extract_all()
                    print(f"RAG: extracted {len(rita_features)} RITA threat(s)")
                else:
                    print("RAG: RITA unavailable, using LSTM-only features")

                print("RAG: merging RITA and LSTM detection results...")
                merged_features = merge_threat_features(rita_features, lstm_results)

                if not merged_features:
                    print("RAG: no threats found after merging, skipping attribution")
                else:
                    print("RAG: searching the knowledge base for every merged threat...")
                    rag_engine = ThreatAttributionEngine(kb_path=APP_ROOT / "chroma_db")
                    rag_context, _ = _build_sample_rag_context(rag_engine, merged_features)
            else:
                print("RAG: no threats detected by RITA or LSTM, skipping attribution")
        except Exception as exc:
            print(f"RAG: failed - {exc}")
            import traceback

            traceback.print_exc()

    analysis_markdown = generate_ai_analysis(
        csv_text,
        lstm_results=lstm_results,
        model_config=get_model_config(None),
        rita_ok=rita_ok,
        rag_context=rag_context,
    )

    response = AnalyzeResponse(
        name=name,
        csv_path="",
        analysis_markdown=analysis_markdown,
    )
    _cleanup_guest_artifacts(artifacts)
    return response


@app.post("/analyze/stream")
async def analyze_pcap_stream(
    pcap: UploadFile = File(...),
    model_id: str | None = Form(None),
    analysis_id: str | None = Form(None),
    user: User | None = Depends(get_optional_current_user),
) -> StreamingResponse:
    model_config = get_model_config(model_id)
    analysis_id = (analysis_id or uuid.uuid4().hex).strip()
    if not analysis_id or len(analysis_id) > 128:
        raise HTTPException(status_code=422, detail="Invalid analysis_id")

    job = AnalysisJob()
    with ACTIVE_ANALYSES_LOCK:
        _prune_pending_cancellations()
        if analysis_id in ACTIVE_ANALYSES:
            raise HTTPException(status_code=409, detail="Analysis task is already running")
        was_cancelled_before_start = analysis_id in PENDING_CANCELLATIONS
        PENDING_CANCELLATIONS.pop(analysis_id, None)
        ACTIVE_ANALYSES[analysis_id] = job
    if was_cancelled_before_start:
        job.cancel_event.set()

    def stream():
        record_id: int | None = None
        artifacts: AnalysisArtifacts | None = None
        try:
            _raise_if_cancelled(job)
            artifacts = _allocate_artifacts(pcap.filename, user)
            name = artifacts.analysis_uuid
            rita_db_name = make_rita_db_name(name)
            upload_path = artifacts.input_path
            output_dir = artifacts.zeek_dir

            _save_uploaded_pcap(pcap, upload_path, job)
            sha256 = _file_sha256(upload_path)
            file_size = upload_path.stat().st_size
            _write_manifest(
                artifacts,
                status="processing",
                original_filename=pcap.filename or "upload.pcap",
                user=user,
                rita_db_name=rita_db_name,
                model_config=model_config,
                sha256=sha256,
                file_size=file_size,
            )
            _append_runtime_log(artifacts, "Upload saved; analysis started")
            if user:
                record_id = create_analysis_record(
                    user_id=user.id,
                    original_filename=pcap.filename or "upload.pcap",
                    storage_path=str(artifacts.root),
                    sha256=sha256,
                    file_size=file_size,
                    model_id=model_config.key,
                )

            yield sse_event("step", "zeek")
            run_zeek(str(upload_path), output_dir, job=job)
            _append_runtime_log(artifacts, "Zeek completed")
            _raise_if_cancelled(job)

            zeek_logs = list(output_dir.glob("*.log"))
            if not zeek_logs:
                raise HTTPException(
                    status_code=500, detail="Zeek did not produce any log files"
                )

            yield sse_event("step", "rita")
            rita_ok = False
            rita_imported = False
            csv_text = ""

            try:
                print(f"RITA: importing logs from {output_dir} ...")
                run_command(
                    ["rita", "import", f"--database={rita_db_name}", f"--logs={output_dir}"],
                    timeout=600,
                    job=job,
                )
                rita_imported = True
                print("RITA: import OK")
            except HTTPException as exc:
                print(f"RITA: import failed - {exc.detail}")
            else:
                try:
                    print(f"RITA: exporting view for db={rita_db_name} ...")
                    view_result = run_command(
                        ["rita", "view", "--stdout", rita_db_name],
                        timeout=120,
                        job=job,
                    )
                    csv_text = view_result.stdout
                    rita_ok = True
                    print(f"RITA: view OK ({len(csv_text)} chars)")
                except AnalysisCancelled:
                    raise
                except HTTPException as exc:
                    print(f"RITA: view failed - {exc.detail}")

            if not rita_ok:
                csv_text = _collect_zeek_logs(output_dir)
                print(f"RITA: falling back to raw Zeek logs ({len(csv_text)} chars)")

            if rita_ok:
                (artifacts.rita_dir / "view.csv").write_text(csv_text, encoding="utf-8")
                _append_runtime_log(artifacts, "RITA view exported")
            else:
                _append_runtime_log(artifacts, "RITA unavailable; AI analysis will use Zeek logs")
            _write_json(
                artifacts.rita_dir / "metadata.json",
                {"available": rita_ok, "imported": rita_imported, "database": rita_db_name},
            )

            yield sse_event("step", "lstm")
            _raise_if_cancelled(job)
            lstm_results = None
            lstm_csv_text = ""
            if _LSTM_AVAILABLE:
                try:
                    from app.pcap_lstm_feature_extractor import export_lstm_features_from_pcap

                    print("LSTM: extracting all-TCP connection features from PCAP packet timestamps")
                    lstm_csv_text = export_lstm_features_from_pcap(upload_path)

                    if lstm_csv_text:
                        (artifacts.lstm_dir / "features.csv").write_text(
                            lstm_csv_text, encoding="utf-8"
                        )
                        print("LSTM: feature extraction complete, running beacon detection...")
                        lstm_results = predict_beacons(lstm_csv_text)
                        _raise_if_cancelled(job)
                    else:
                        print("LSTM: skipped (no usable TCP connection sequence found in PCAP)")
                except AnalysisCancelled:
                    raise
                except Exception as exc:
                    print(f"LSTM: analysis failed - {exc}")
                    import traceback

                    traceback.print_exc()
            _write_json(
                artifacts.lstm_dir / "result.json",
                lstm_results
                or {
                    "status": "skipped_or_failed",
                    "reason": "No usable TCP sequence, unavailable dependency, or prediction failure",
                },
            )
            _append_runtime_log(
                artifacts,
                "LSTM completed" if lstm_results is not None else "LSTM skipped or failed",
            )

            yield sse_event("step", "rag")
            _raise_if_cancelled(job)
            rag_context = None
            merged_features: list[dict] = []
            rag_result: dict | None = None
            if not _RAG_AVAILABLE:
                print(
                    "RAG: skipped (dependencies not installed: chromadb or sentence-transformers)"
                )
            else:
                try:
                    rita_features = []
                    if rita_ok:
                        print("RAG: extracting RITA threat features from RITA CSV...")
                        extractor = ThreatFeatureExtractor(csv_text)
                        rita_features = extractor.extract_all()
                        print(f"RAG: extracted {len(rita_features)} RITA threat(s)")
                    else:
                        print("RAG: RITA unavailable, using LSTM-only features")

                    if rita_features or (
                        lstm_results and lstm_results.get("total_flagged", 0) > 0
                    ):
                        from app.threat_feature_merger import merge_threat_features

                        rita_evidence = {}
                        if rita_imported:
                            try:
                                from app.rita_feature_exporter import export_rita_connection_evidence
                                rita_evidence = export_rita_connection_evidence(rita_db_name)
                            except Exception as exc:
                                print(f"RITA: detailed mixtape evidence unavailable - {exc}")
                        print("RAG: merging RITA and LSTM detection results...")
                        merged_features = merge_threat_features(rita_features, lstm_results, rita_evidence)

                        if not merged_features:
                            print("RAG: no threats found after merging, skipping attribution")
                        else:
                            print(
                                f"RAG: merged features ready ({len(merged_features)} unique threats)"
                            )
                            print("RAG: initializing knowledge base + embedding model...")
                            rag_engine = ThreatAttributionEngine(
                                kb_path=APP_ROOT / "chroma_db"
                            )
                            print(
                                f"RAG: searching for matching APT groups (top-{rag_engine.top_k})..."
                            )

                            rag_context, rag_results = _build_sample_rag_context(
                                rag_engine, merged_features, job=job
                            )
                            _raise_if_cancelled(job)
                            rag_result = rag_results[0] if rag_results else None
                    else:
                        print("RAG: no threats detected by RITA or LSTM, skipping attribution")
                except AnalysisCancelled:
                    raise
                except Exception as exc:
                    print(f"RAG: failed - {exc}")
                    import traceback

                    traceback.print_exc()
            _write_json(artifacts.merged_dir / "threats.json", merged_features)
            _write_json(
                artifacts.rag_dir / "result.json",
                rag_result or {"status": "skipped_or_no_candidates"},
            )
            if rag_context:
                (artifacts.rag_dir / "context.md").write_text(rag_context, encoding="utf-8")
            _append_runtime_log(
                artifacts,
                "RAG completed" if rag_result is not None else "RAG skipped or no candidates",
            )

            yield sse_event("step", "ai")
            _raise_if_cancelled(job)
            chunks: list[str] = []
            for delta in stream_ai_analysis(
                csv_text,
                lstm_results=lstm_results,
                model_config=model_config,
                rita_ok=rita_ok,
                rag_context=rag_context,
                job=job,
            ):
                chunks.append(delta)
                yield sse_event(
                    "delta",
                    json.dumps({"content": delta}, ensure_ascii=False),
                )

            analysis_markdown = "".join(chunks)
            analysis_markdown += _lstm_evidence_appendix(lstm_results)
            analysis_markdown += _rag_evidence_appendix(rag_context)
            report_path = artifacts.report_dir / "analysis.md"
            report_path.write_text(analysis_markdown, encoding="utf-8")
            dashboard = {
                "schema_version": ARTIFACT_SCHEMA_VERSION,
                "analysis_uuid": name,
                "display_name": artifacts.display_name,
                "engine_status": {
                    "rita_available": rita_ok,
                    "lstm_completed": lstm_results is not None,
                    "rag_completed": rag_result is not None,
                },
                "threats": merged_features,
                "attribution": rag_result,
                "lstm": lstm_results or {"status": "skipped_or_failed", "beacons": []},
                "rita": {
                    "available": rita_ok,
                    "database": rita_db_name,
                    "detailed_evidence_available": bool(rita_imported),
                },
            }
            _write_json(artifacts.visualization_dir / "dashboard.json", dashboard)
            _write_manifest(
                artifacts,
                status="completed",
                original_filename=pcap.filename or "upload.pcap",
                user=user,
                rita_db_name=rita_db_name,
                model_config=model_config,
                sha256=sha256,
                file_size=file_size,
            )
            _append_runtime_log(artifacts, "AI report and visualization data saved")
            if record_id:
                finish_analysis_record(
                    record_id,
                    status="completed",
                    result_json=dashboard,
                    report_markdown=analysis_markdown,
                    report_path=str(report_path),
                )
            payload = json.dumps(
                {
                    "name": name,
                    "display_name": artifacts.display_name,
                    "analysis_markdown": analysis_markdown,
                    "visualization": dashboard,
                },
                ensure_ascii=False,
            )
            yield sse_event("result", payload)
        except AnalysisCancelled:
            if record_id:
                finish_analysis_record(record_id, status="cancelled")
            if artifacts:
                _set_manifest_status(artifacts, "cancelled")
                _append_runtime_log(artifacts, "Analysis cancelled")
            yield sse_event("cancelled", json.dumps({"analysis_id": analysis_id}))
        except HTTPException as exc:
            if record_id:
                finish_analysis_record(record_id, status="failed")
            if artifacts:
                _set_manifest_status(artifacts, "failed", exc.detail)
                _append_runtime_log(artifacts, f"Analysis failed: {exc.detail}")
            yield sse_event("error", exc.detail)
        except Exception:
            if record_id:
                finish_analysis_record(record_id, status="failed")
            if artifacts:
                _set_manifest_status(artifacts, "failed", "Unexpected analysis error")
                _append_runtime_log(artifacts, "Analysis failed with an unexpected error")
            yield sse_event("error", "分析任务执行失败，请稍后重试")
        finally:
            if not user:
                _cleanup_guest_artifacts(artifacts)
            with ACTIVE_ANALYSES_LOCK:
                ACTIVE_ANALYSES.pop(analysis_id, None)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream; charset=utf-8",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

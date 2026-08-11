import json
import hashlib
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
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
    finish_analysis_record,
)
from app.auth import initialise_session_secret, get_optional_current_user, router as auth_router

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
UPLOADS_DIR = APP_ROOT / "uploads"
OUTPUTS_DIR = APP_ROOT / "outputs"

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
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)


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
    rag_engine: ThreatAttributionEngine,
    merged_features: list[dict],
    *,
    job: AnalysisJob | None = None,
) -> tuple[str, list[dict]]:
    """Build an auditable, sample-level RAG context for every suspicious flow.

    A PCAP can contain more than one suspicious connection.  This deliberately
    performs a separate retrieval for each merged RITA/LSTM feature instead of
    selecting the first item in ``merged_features``.  The returned text is both
    supplied to the LLM and appended to the final report as a deterministic
    evidence appendix, so no detected connection can be silently omitted by
    report generation.
    """
    results: list[dict] = []
    lines = [
        f"本样本共检出 **{len(merged_features)}** 条唯一可疑连接。",
        "以下编号是该样本内的连接编号；每条连接均已独立完成 RAG 检索。",
    ]

    for index, feature in enumerate(merged_features, 1):
        _raise_if_cancelled(job)
        sources = feature.get("detection_sources") or []
        if isinstance(sources, str):
            sources = [item for item in sources.split(";") if item]
        source_text = " + ".join(sources) if sources else "未知"
        endpoint = (
            f"{feature.get('src_ip') or 'unknown'} → "
            f"{feature.get('dst_ip') or 'unknown'}:"
            f"{feature.get('dst_port') or 'unknown'}"
        )
        try:
            beacon_score = float(feature.get("beacon_score") or 0)
        except (TypeError, ValueError):
            beacon_score = 0.0
        try:
            lstm_confidence = float(feature.get("lstm_confidence") or 0)
        except (TypeError, ValueError):
            lstm_confidence = 0.0

        try:
            result = rag_engine.attribute_single_threat(feature)
            results.append(result)
            candidates = result.get("candidates") or []
            techniques = result.get("matched_techniques") or []

            lines.extend(
                [
                    f"\n### 可疑连接 {index}",
                    f"- **连接**：{endpoint}（协议：{feature.get('protocol') or 'unknown'}）",
                    f"- **检测来源**：{source_text}",
                    f"- **RITA Beacon 评分**：{beacon_score:.1f}/100",
                    f"- **LSTM 置信度**：{lstm_confidence:.1f}%",
                    "- **ATT&CK 技术**："
                    + (", ".join(techniques) if techniques else "未从检索结果中确定"),
                ]
            )
            if candidates:
                candidate_text = "; ".join(
                    f"{candidate.get('name', 'unknown')} "
                    f"({float(candidate.get('score') or 0):.3f})"
                    for candidate in candidates[:3]
                )
                lines.append(f"- **RAG 候选组织（Top-{min(3, len(candidates))}）**：{candidate_text}")
                lines.append(
                    "- **归因说明**：候选反映知识库语义相似度，不等同于已确认的攻击组织。"
                )
            else:
                lines.append("- **RAG 候选组织**：未检索到可用候选。")
        except AnalysisCancelled:
            raise
        except Exception as exc:
            # One malformed connection must not hide the rest of the sample.
            print(f"RAG: retrieval failed for threat {index}/{len(merged_features)} - {exc}")
            lines.extend(
                [
                    f"\n### 可疑连接 {index}",
                    f"- **连接**：{endpoint}（协议：{feature.get('protocol') or 'unknown'}）",
                    f"- **检测来源**：{source_text}",
                    f"- **RITA Beacon 评分**：{beacon_score:.1f}/100",
                    f"- **LSTM 置信度**：{lstm_confidence:.1f}%",
                    "- **RAG 状态**：该连接检索失败；其检测证据仍保留在本报告中。",
                ]
            )

    return "\n".join(lines), results


def _rag_evidence_appendix(rag_context: str | None) -> str:
    """Return a deterministic report appendix containing all detected flows."""
    if not rag_context:
        return ""
    return f"\n\n---\n\n## 附录：系统生成的全量可疑连接与 RAG 检索证据\n\n{rag_context}"


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
            "\n以下是系统对该样本全部可疑连接生成的 ATT&CK/RAG 证据。"
            "它是检测结论的事实依据，不得遗漏其中任一编号连接：\n"
            f"{rag_context}\n\n"
            "请在报告中新增以下章节：\n"
            "5. **可疑连接全量分析** - 按连接编号逐条说明检测来源、关键行为和风险；"
            "不得只分析第一条连接。\n"
            "6. **威胁归因** - 汇总 ATT&CK 技术和候选组织；明确候选组织仅为线索，"
            "不得将语义检索结果表述为已确认归因。\n"
        )

    if lstm_results and lstm_results.get("total_flagged", 0) > 0:
        lstm_markdown = _fmt_lstm(lstm_results)
        prompt += f"\nLSTM 检测结果如下：\n{lstm_markdown}\n"
        print("=" * 80)
        print("LSTM Beacon Detection Results (inserted into LLM prompt):")
        print("=" * 80)
        print(lstm_markdown)
        print("=" * 80)
    elif lstm_results and lstm_results.get("total_flagged", 0) == 0:
        print("LSTM: analyzed but found no beacons")

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
        return report + _rag_evidence_appendix(rag_context)
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


def _cleanup_guest_artifacts(
    upload_path: Path | None, output_dir: Path | None, csv_path: Path | None
) -> None:
    """Remove transient files after an anonymous analysis has been streamed."""

    for file_path in (upload_path, csv_path):
        if file_path:
            try:
                file_path.unlink(missing_ok=True)
            except OSError:
                pass
    if output_dir:
        try:
            shutil.rmtree(output_dir, ignore_errors=True)
        except OSError:
            pass


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
    ensure_dirs()

    name = uuid.uuid4().hex
    rita_db_name = make_rita_db_name(name)
    upload_path = UPLOADS_DIR / f"{name}.pcap"
    output_dir = OUTPUTS_DIR / name
    output_dir.mkdir(parents=True, exist_ok=True)

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

    csv_path = OUTPUTS_DIR / f"{name}.csv"
    csv_path.write_text(csv_text, encoding="utf-8")

    # The LSTM consumes reconstructed TCP connection events directly from the
    # capture. DNS/UDP traffic remains on the RITA/RAG path.
    lstm_results = None
    if _LSTM_AVAILABLE:
        try:
            from app.pcap_lstm_feature_extractor import export_lstm_features_from_pcap

            print("LSTM: extracting all-TCP connection timing features from PCAP packet timestamps")
            lstm_csv_text = export_lstm_features_from_pcap(upload_path)

            if lstm_csv_text:
                print("LSTM: feature extraction complete, running beacon detection...")
                lstm_results = predict_beacons(lstm_csv_text)
            else:
                print("LSTM: skipped (no HTTP/HTTPS packets found in PCAP)")
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
                    print(
                        f"RAG: merged features ready ({len(merged_features)} unique threats), "
                        "searching knowledge base for every threat..."
                    )
                    rag_engine = ThreatAttributionEngine(kb_path=APP_ROOT / "chroma_db")
                    rag_context, rag_results = _build_sample_rag_context(
                        rag_engine, merged_features
                    )
                    matched_count = sum(bool(result.get("candidates")) for result in rag_results)
                    print(
                        f"RAG: completed {len(merged_features)} threat retrieval(s), "
                        f"{matched_count} with candidate groups"
                    )
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

    return AnalyzeResponse(
        name=name,
        csv_path=str(csv_path),
        analysis_markdown=analysis_markdown,
    )


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
        upload_path: Path | None = None
        output_dir: Path | None = None
        csv_path: Path | None = None
        try:
            _raise_if_cancelled(job)
            ensure_dirs()

            name = uuid.uuid4().hex
            rita_db_name = make_rita_db_name(name)
            upload_path = UPLOADS_DIR / f"{name}.pcap"
            output_dir = OUTPUTS_DIR / name
            output_dir.mkdir(parents=True, exist_ok=True)

            _save_uploaded_pcap(pcap, upload_path, job)
            if user:
                record_id = create_analysis_record(
                    user_id=user.id,
                    original_filename=pcap.filename or "upload.pcap",
                    storage_path=str(upload_path),
                    sha256=_file_sha256(upload_path),
                    file_size=upload_path.stat().st_size,
                    model_id=model_config.key,
                )

            yield sse_event("step", "zeek")
            run_zeek(str(upload_path), output_dir, job=job)
            _raise_if_cancelled(job)

            zeek_logs = list(output_dir.glob("*.log"))
            if not zeek_logs:
                raise HTTPException(
                    status_code=500, detail="Zeek did not produce any log files"
                )

            yield sse_event("step", "rita")
            rita_ok = False
            csv_text = ""

            try:
                print(f"RITA: importing logs from {output_dir} ...")
                run_command(
                    ["rita", "import", f"--database={rita_db_name}", f"--logs={output_dir}"],
                    timeout=600,
                    job=job,
                )
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

            csv_path = OUTPUTS_DIR / f"{name}.csv"
            csv_path.write_text(csv_text, encoding="utf-8")

            yield sse_event("step", "lstm")
            _raise_if_cancelled(job)
            lstm_results = None
            if _LSTM_AVAILABLE:
                try:
                    from app.pcap_lstm_feature_extractor import export_lstm_features_from_pcap

                    print("LSTM: extracting all-TCP connection timing features from PCAP packet timestamps")
                    lstm_csv_text = export_lstm_features_from_pcap(upload_path)

                    if lstm_csv_text:
                        print("LSTM: feature extraction complete, running beacon detection...")
                        lstm_results = predict_beacons(lstm_csv_text)
                        _raise_if_cancelled(job)
                    else:
                        print("LSTM: skipped (no HTTP/HTTPS packets found in PCAP)")
                except AnalysisCancelled:
                    raise
                except Exception as exc:
                    print(f"LSTM: analysis failed - {exc}")
                    import traceback

                    traceback.print_exc()

            yield sse_event("step", "rag")
            _raise_if_cancelled(job)
            rag_context = None
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

                        print("RAG: merging RITA and LSTM detection results...")
                        merged_features = merge_threat_features(rita_features, lstm_results)

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
                            matched_count = sum(
                                bool(result.get("candidates")) for result in rag_results
                            )
                            print(
                                f"RAG: completed {len(merged_features)} threat retrieval(s), "
                                f"{matched_count} with candidate groups"
                            )
                    else:
                        print("RAG: no threats detected by RITA or LSTM, skipping attribution")
                except AnalysisCancelled:
                    raise
                except Exception as exc:
                    print(f"RAG: failed - {exc}")
                    import traceback

                    traceback.print_exc()

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
            analysis_markdown += _rag_evidence_appendix(rag_context)
            if record_id:
                finish_analysis_record(
                    record_id,
                    status="completed",
                    result_json={
                        "rita_available": rita_ok,
                        "lstm_completed": lstm_results is not None,
                        "rag_completed": rag_context is not None,
                    },
                    report_markdown=analysis_markdown,
                )
            payload = json.dumps(
                {
                    "name": name,
                    "csv_path": str(csv_path),
                    "analysis_markdown": analysis_markdown,
                },
                ensure_ascii=False,
            )
            yield sse_event("result", payload)
        except AnalysisCancelled:
            if record_id:
                finish_analysis_record(record_id, status="cancelled")
            yield sse_event("cancelled", json.dumps({"analysis_id": analysis_id}))
        except HTTPException as exc:
            if record_id:
                finish_analysis_record(record_id, status="failed")
            yield sse_event("error", exc.detail)
        except Exception:
            if record_id:
                finish_analysis_record(record_id, status="failed")
            yield sse_event("error", "分析任务执行失败，请稍后重试")
        finally:
            if not user:
                _cleanup_guest_artifacts(upload_path, output_dir, csv_path)
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

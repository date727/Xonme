import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Ensure backend/ is on sys.path so `from app.xxx` imports work
# regardless of whether uvicorn is started from project root or backend/
_sys_path_root = Path(__file__).resolve().parent.parent  # backend/
if str(_sys_path_root) not in sys.path:
    sys.path.insert(0, str(_sys_path_root))

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

SILICONFLOW_BASE_URL = os.getenv("SILICONFLOW_BASE_URL", "").rstrip("/")
SILICONFLOW_API_KEY = os.getenv("SILICONFLOW_API_KEY", "")
SILICONFLOW_MODEL = os.getenv("SILICONFLOW_MODEL", "")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeResponse(BaseModel):
    name: str
    csv_path: str
    analysis_markdown: str


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


def run_command(
    cmd: list[str], cwd: Path | None = None, timeout: int | None = None
) -> None:
    """Run a subprocess, raising HTTPException on failure or timeout."""

    try:
        subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Command timed out after {timeout}s: {' '.join(cmd)}",
        ) from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        detail = stderr or stdout or "Command failed"
        raise HTTPException(status_code=500, detail=detail) from exc


def run_zeek(pcap_path: str, output_dir: Path) -> None:
    """Run Zeek on a PCAP file, trying standard CLI first, then readpcap."""

    try:
        run_command(
            ["zeek", "-r", pcap_path, "-C", "LogAscii::use_json=F"],
            cwd=output_dir,
        )
        return
    except HTTPException:
        pass

    run_command(["zeek", "readpcap", pcap_path, str(output_dir)])


def _build_ai_request(
    csv_text: str,
    lstm_results: dict | None = None,
    *,
    rita_ok: bool = True,
    rag_context: str | None = None,
    stream: bool = False,
) -> tuple[str, dict[str, str], dict]:
    if not SILICONFLOW_BASE_URL or not SILICONFLOW_API_KEY or not SILICONFLOW_MODEL:
        raise HTTPException(
            status_code=500, detail="Missing SiliconFlow API configuration"
        )

    url = f"{SILICONFLOW_BASE_URL}/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {SILICONFLOW_API_KEY}",
        "Content-Type": "application/json",
    }

    source = "RITA CSV report" if rita_ok else "Zeek network log data"
    system_prompt = (
        "你是一名资深网络威胁分析师。"
        "请始终使用中文回答，并输出专业的 Markdown 报告。"
    )

    prompt = (
        "# C2Sherlock AI分析报告\n\n"
        f"请分析以下{source}，并按下面结构组织内容：\n"
        "1. 执行摘要：用 2 到 3 句话概括核心发现。\n"
        "2. 主要威胁特征：说明可疑 C2 行为、Beacon 特征和异常现象。\n"
        "3. 风险评估：说明严重性、潜在影响与业务风险。\n"
        "4. 处置建议：给出面向 SOC 团队的具体下一步措施。\n"
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
        "model": SILICONFLOW_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "enable_thinking": False,
    }
    if stream:
        payload["stream"] = True

    return url, headers, payload


def generate_ai_analysis(
    csv_text: str,
    lstm_results: dict | None = None,
    *,
    rita_ok: bool = True,
    rag_context: str | None = None,
) -> str:
    url, headers, payload = _build_ai_request(
        csv_text,
        lstm_results=lstm_results,
        rita_ok=rita_ok,
        rag_context=rag_context,
        stream=False,
    )

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=120)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="SiliconFlow API request failed") from exc

    data = response.json()
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, AttributeError) as exc:
        raise HTTPException(
            status_code=502, detail="Unexpected SiliconFlow response format"
        ) from exc


def stream_ai_analysis(
    csv_text: str,
    lstm_results: dict | None = None,
    *,
    rita_ok: bool = True,
    rag_context: str | None = None,
):
    url, headers, payload = _build_ai_request(
        csv_text,
        lstm_results=lstm_results,
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
        raise HTTPException(status_code=502, detail="SiliconFlow API request failed") from exc

    try:
        for raw_line in response.iter_lines(decode_unicode=True):
            if not raw_line:
                continue

            line = raw_line.strip()
            if not line.startswith("data:"):
                continue

            data = line[5:].strip()
            if data == "[DONE]":
                break

            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue

            choice = chunk.get("choices", [{}])[0]
            delta_obj = choice.get("delta", {})
            delta = delta_obj.get("content") or delta_obj.get("reasoning_content") or ""
            if delta:
                yield delta
    finally:
        response.close()


def sse_event(event: str, data: str) -> str:
    return f"event: {event}\ndata: {data}\n\n"


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

    # The current model is trained for HTTP/HTTPS, so DNS and other traffic
    # stays in the RITA/RAG path instead of being sent to the LSTM.
    lstm_results = None
    if _LSTM_AVAILABLE:
        try:
            from app.zeek_to_lstm_converter import export_lstm_features_from_zeek

            print("LSTM: extracting HTTP/HTTPS features from Zeek conn.log")
            lstm_csv_text = export_lstm_features_from_zeek(output_dir)

            if lstm_csv_text:
                print("LSTM: feature extraction complete, running beacon detection...")
                lstm_results = predict_beacons(lstm_csv_text)
            else:
                print("LSTM: skipped (no HTTP/HTTPS connections found in conn.log)")
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
                    print("RAG: merged features ready, searching knowledge base...")
                    rag_engine = ThreatAttributionEngine(kb_path=APP_ROOT / "chroma_db")
                    rag_result = rag_engine.attribute_single_threat(merged_features[0])

                    if rag_result["candidates"]:
                        primary = rag_result["primary_candidate"]
                        print(
                            f"RAG: matched! primary={primary['name']}, "
                            f"confidence={rag_result['confidence']:.1f}%"
                        )
                        rag_context = rag_engine.generate_attribution_report(rag_result)
                    else:
                        print("RAG: no matching APT group found in knowledge base")
            else:
                print("RAG: no threats detected by RITA or LSTM, skipping attribution")
        except Exception as exc:
            print(f"RAG: failed - {exc}")
            import traceback

            traceback.print_exc()

    analysis_markdown = generate_ai_analysis(
        csv_text,
        lstm_results=lstm_results,
        rita_ok=rita_ok,
        rag_context=rag_context,
    )

    return AnalyzeResponse(
        name=name,
        csv_path=str(csv_path),
        analysis_markdown=analysis_markdown,
    )


@app.post("/analyze/stream")
async def analyze_pcap_stream(pcap: UploadFile = File(...)) -> StreamingResponse:
    def stream():
        ensure_dirs()

        name = uuid.uuid4().hex
        rita_db_name = make_rita_db_name(name)
        upload_path = UPLOADS_DIR / f"{name}.pcap"
        output_dir = OUTPUTS_DIR / name
        output_dir.mkdir(parents=True, exist_ok=True)

        with upload_path.open("wb") as file_obj:
            shutil.copyfileobj(pcap.file, file_obj)

        try:
            yield sse_event("step", "zeek")
            run_zeek(str(upload_path), output_dir)

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

            yield sse_event("step", "lstm")
            lstm_results = None
            if _LSTM_AVAILABLE:
                try:
                    from app.zeek_to_lstm_converter import export_lstm_features_from_zeek

                    print("LSTM: extracting HTTP/HTTPS features from Zeek conn.log")
                    lstm_csv_text = export_lstm_features_from_zeek(output_dir)

                    if lstm_csv_text:
                        print("LSTM: feature extraction complete, running beacon detection...")
                        lstm_results = predict_beacons(lstm_csv_text)
                    else:
                        print("LSTM: skipped (no HTTP/HTTPS connections found in conn.log)")
                except Exception as exc:
                    print(f"LSTM: analysis failed - {exc}")
                    import traceback

                    traceback.print_exc()

            yield sse_event("step", "rag")
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

                            rag_result = rag_engine.attribute_single_threat(
                                merged_features[0]
                            )

                            if rag_result["candidates"]:
                                primary = rag_result["primary_candidate"]
                                print(
                                    f"RAG: matched! primary={primary['name']}, "
                                    f"confidence={rag_result['confidence']:.1f}%, "
                                    f"candidates={len(rag_result['candidates'])}"
                                )
                                rag_context = rag_engine.generate_attribution_report(
                                    rag_result
                                )
                            else:
                                print("RAG: no matching APT group found in knowledge base")
                    else:
                        print("RAG: no threats detected by RITA or LSTM, skipping attribution")
                except Exception as exc:
                    print(f"RAG: failed - {exc}")
                    import traceback

                    traceback.print_exc()

            yield sse_event("step", "ai")
            chunks: list[str] = []
            for delta in stream_ai_analysis(
                csv_text,
                lstm_results=lstm_results,
                rita_ok=rita_ok,
                rag_context=rag_context,
            ):
                chunks.append(delta)
                yield sse_event(
                    "delta",
                    json.dumps({"content": delta}, ensure_ascii=False),
                )

            analysis_markdown = "".join(chunks)
            payload = json.dumps(
                {
                    "name": name,
                    "csv_path": str(csv_path),
                    "analysis_markdown": analysis_markdown,
                },
                ensure_ascii=False,
            )
            yield sse_event("result", payload)
        except HTTPException as exc:
            yield sse_event("error", exc.detail)

    return StreamingResponse(stream(), media_type="text/event-stream")

import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import requests

# Ensure backend/ is on sys.path so `from app.xxx` imports work
# regardless of whether uvicorn is started from project root or backend/
_sys_path_root = Path(__file__).resolve().parent.parent  # backend/
if str(_sys_path_root) not in sys.path:
    sys.path.insert(0, str(_sys_path_root))

# LSTM beacon detection — gracefully degrades if dependencies are missing
try:
    from app.lstm_predictor import predict_beacons, format_for_prompt as _fmt_lstm
    from app.rita_feature_exporter import export_lstm_feature_csv_from_rita_db

    _LSTM_AVAILABLE = True
except ImportError:
    _LSTM_AVAILABLE = False

# RAG engine — core pipeline (Zeek → RITA → RAG → AI)
try:
    from app.rag_engine import ThreatAttributionEngine
    from app.data_extractor import ThreatFeatureExtractor
    _RAG_AVAILABLE = True
except ImportError as e:
    print(f"⚠ RAG disabled — import failed: {e}")
    _RAG_AVAILABLE = False

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

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
    allow_methods=["*"] ,
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

    RITA v5 rejects some raw UUID hex names (for example names that start
    with a digit). Prefix with a letter to keep names deterministic and valid.
    """
    return f"run_{run_id}"


def _collect_zeek_logs(log_dir: Path) -> str:
    """Read all Zeek TSV log files and return them as a single text blob.

    Used as fallback when RITA import/view fails, so the LLM still has
    raw Zeek data to analyse.
    """
    parts: list[str] = []
    for log_path in sorted(log_dir.glob("*.log")):
        try:
            content = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Strip Zeek header lines (#separator, #set_separator, #empty_field, #unset_field)
        # but keep #fields and #types so the LLM can understand column layout
        lines = content.splitlines()
        filtered = [ln for ln in lines if not ln.startswith("#separator")]
        parts.append(f"=== {log_path.name} ===\n" + "\n".join(filtered))
    return "\n\n".join(parts) if parts else "(No Zeek logs found)"


def run_command(
    cmd: list[str], cwd: Path | None = None, timeout: int | None = None
) -> None:
    """Run a subprocess, raise HTTPException(500) on non-zero exit or timeout."""
    try:
        subprocess.run(
            cmd, cwd=cwd, check=True, capture_output=True, text=True, timeout=timeout
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
    """Run Zeek on a PCAP file, trying standard CLI first, then readpcap fallback.

    Standard:  zeek -r <pcap> -C LogAscii::use_json=F  (cwd = output_dir)
    Fallback:  zeek readpcap <pcap> <output_dir>
    """
    try:
        run_command(
            ["zeek", "-r", pcap_path, "-C", "LogAscii::use_json=F"],
            cwd=output_dir,
        )
        return
    except HTTPException:
        pass

    run_command(
        ["zeek", "readpcap", pcap_path, str(output_dir)],
    )


def extract_threat_features(csv_text: str, output_dir: Path) -> list[dict]:
    """
    从 RITA CSV 和 Zeek 日志中提取威胁特征
    
    Args:
        csv_text: RITA CSV 输出
        output_dir: Zeek 日志目录
    
    Returns:
        威胁特征列表
    """
    try:
        from app.data_extractor import ThreatFeatureExtractor
        extractor = ThreatFeatureExtractor(csv_text, output_dir)
        return extractor.extract_all()
    except Exception as e:
        print(f"⚠ 威胁特征提取失败: {e}")
        return []


def generate_ai_analysis(
    csv_text: str,
    lstm_results: dict | None = None,
    *,
    rita_ok: bool = True,
    rag_context: str | None = None,
) -> str:
    if not SILICONFLOW_BASE_URL or not SILICONFLOW_API_KEY or not SILICONFLOW_MODEL:
        raise HTTPException(status_code=500, detail="Missing SiliconFlow API configuration")

    url = f"{SILICONFLOW_BASE_URL}/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {SILICONFLOW_API_KEY}",
        "Content-Type": "application/json",
    }

    source = "RITA CSV report" if rita_ok else "Zeek network log data"

    # System prompt
    system_prompt = "You are a senior threat intelligence analyst. Provide thorough, well-structured analysis in Markdown."

    # User prompt — base
    prompt = (
        f"Review the following {source} and produce a comprehensive report with these sections:\n"
        "1. **Executive Summary** — high-level findings in 2-3 sentences\n"
        "2. **Key Threats Identified** — notable C2 behaviors, beaconing patterns, anomalies\n"
        "3. **Risk Assessment** — severity and potential impact\n"
        "4. **Recommended Actions** — concrete next steps for the SOC team\n\n"
    )

    # Inject RAG attribution context into the prompt when available
    if rag_context:
        prompt += (
            "---\n"
            "**ATT&CK Context for Attribution** (use this to enrich your analysis):\n"
            f"{rag_context}\n"
            "---\n\n"
            "In your report, add a section **5. Threat Attribution** that:\n"
            "- Names the most likely APT group(s) based on TTP overlap\n"
            "- Cites the matched MITRE ATT&CK techniques\n"
            "- Notes your confidence level and any caveats\n\n"
        )

    # Augment with LSTM results
    if lstm_results and lstm_results.get("total_flagged", 0) > 0:
        prompt += _fmt_lstm(lstm_results) + "\n\n---\n\n"

    prompt += csv_text

    payload = {
        "model": SILICONFLOW_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=120)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="SiliconFlow API request failed") from exc

    data = response.json()
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, AttributeError) as exc:
        raise HTTPException(status_code=502, detail="Unexpected SiliconFlow response format") from exc


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

    with upload_path.open("wb") as f:
        shutil.copyfileobj(pcap.file, f)

    run_zeek(str(upload_path), output_dir)

    # Verify Zeek produced logs before handing off to RITA
    zeek_logs = list(output_dir.glob("*.log"))
    if not zeek_logs:
        raise HTTPException(
            status_code=500, detail="Zeek did not produce any log files"
        )

    # --- RITA import + view (non-blocking: falls back to raw Zeek logs on failure) ---
    rita_ok = False
    csv_text = ""

    try:
        # RITA v5+ may start Docker containers — give it generous timeout
        print(f"⏳ RITA: importing logs from {output_dir} ...")
        run_command(
            ["rita", "import", f"--database={rita_db_name}", f"--logs={output_dir}"],
            timeout=600,
        )
        print("✓ RITA: import OK")
    except HTTPException as exc:
        print(f"⚠ RITA: import failed — {exc.detail}")
    else:
        try:
            print(f"⏳ RITA: exporting view for db={rita_db_name} ...")
            view_result = subprocess.run(
                ["rita", "view", "--stdout", rita_db_name],
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            csv_text = view_result.stdout
            rita_ok = True
            print(f"✓ RITA: view OK ({len(csv_text)} chars)")
        except subprocess.TimeoutExpired:
            print("⚠ RITA: view timed out after 120s")
        except subprocess.CalledProcessError as exc:
            print(f"⚠ RITA: view failed — {(exc.stderr or exc.stdout or '').strip()}")

    if not rita_ok:
        csv_text = _collect_zeek_logs(output_dir)
        print(f"⚠ RITA: falling back to raw Zeek logs ({len(csv_text)} chars)")

    csv_path = OUTPUTS_DIR / f"{name}.csv"
    csv_path.write_text(csv_text, encoding="utf-8")

    # LSTM requires iat_oresp_* feature columns; try exporting from RITA DB first.
    lstm_results = None
    if _LSTM_AVAILABLE and rita_ok:
        lstm_csv_text = csv_text
        try:
            exported = export_lstm_feature_csv_from_rita_db(rita_db_name)
            if exported.strip():
                lstm_csv_text = exported
                print("✓ LSTM: using RITA DB feature export (iat_oresp_*)")
            else:
                print("⚠ LSTM: empty RITA DB feature export, fallback to RITA view output")
        except Exception as e:
            print(f"⚠ LSTM: feature export failed, fallback to RITA view output — {e}")
        lstm_results = predict_beacons(lstm_csv_text)

    # RAG attribution
    rag_context = None
    if not _RAG_AVAILABLE:
        print("⏭ RAG: skipped (dependencies not installed)")
    elif not rita_ok:
        print("⏭ RAG: skipped (RITA unavailable)")
    else:
        try:
            print("🔍 RAG: extracting threat features...")
            extractor = ThreatFeatureExtractor(csv_text, output_dir)
            features = extractor.extract_all()
            print(f"🔍 RAG: extracted {len(features)} threat feature(s)")

            if not features:
                print("⏭ RAG: no high-risk threats found, skipping attribution")
            else:
                print("🔍 RAG: searching knowledge base...")
                rag_engine = ThreatAttributionEngine(kb_path=APP_ROOT / "chroma_db")
                rag_result = rag_engine.attribute_single_threat(features[0])

                if rag_result["candidates"]:
                    primary = rag_result["primary_candidate"]
                    print(f"✓ RAG: matched! primary={primary['name']}, "
                          f"confidence={rag_result['confidence']:.1f}%")
                    rag_context = rag_engine.generate_attribution_report(rag_result)
                else:
                    print("⚠ RAG: no matching APT group found")
        except Exception as e:
            print(f"❌ RAG: failed — {e}")
            import traceback
            traceback.print_exc()

    analysis_markdown = generate_ai_analysis(
        csv_text, lstm_results=lstm_results, rita_ok=rita_ok, rag_context=rag_context,
    )

    return AnalyzeResponse(
        name=name,
        csv_path=str(csv_path),
        analysis_markdown=analysis_markdown,
    )


@app.post("/analyze/stream")
async def analyze_pcap_stream(pcap: UploadFile = File(...)) -> StreamingResponse:
    def stream() -> str:
        ensure_dirs()

        name = uuid.uuid4().hex
        rita_db_name = make_rita_db_name(name)
        upload_path = UPLOADS_DIR / f"{name}.pcap"
        output_dir = OUTPUTS_DIR / name
        output_dir.mkdir(parents=True, exist_ok=True)

        with upload_path.open("wb") as f:
            shutil.copyfileobj(pcap.file, f)

        try:
            yield sse_event("step", "zeek")
            run_zeek(str(upload_path), output_dir)

            # Verify Zeek produced logs before handing off to RITA
            zeek_logs = list(output_dir.glob("*.log"))
            if not zeek_logs:
                raise HTTPException(
                    status_code=500, detail="Zeek did not produce any log files"
                )

            # --- RITA import + view (non-blocking: falls back to raw Zeek logs on failure) ---
            yield sse_event("step", "rita")
            rita_ok = False
            csv_text = ""

            try:
                # RITA v5+ may start Docker containers — give it generous timeout
                print(f"⏳ RITA: importing logs from {output_dir} ...")
                run_command(
                    ["rita", "import", f"--database={rita_db_name}", f"--logs={output_dir}"],
                    timeout=600,
                )
                print("✓ RITA: import OK")
            except HTTPException as exc:
                print(f"⚠ RITA: import failed — {exc.detail}")
            else:
                try:
                    print(f"⏳ RITA: exporting view for db={rita_db_name} ...")
                    view_result = subprocess.run(
                        ["rita", "view", "--stdout", rita_db_name],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    csv_text = view_result.stdout
                    rita_ok = True
                    print(f"✓ RITA: view OK ({len(csv_text)} chars)")
                except subprocess.TimeoutExpired:
                    print("⚠ RITA: view timed out after 120s")
                except subprocess.CalledProcessError as exc:
                    print(f"⚠ RITA: view failed — {(exc.stderr or exc.stdout or '').strip()}")

            if not rita_ok:
                csv_text = _collect_zeek_logs(output_dir)
                print(f"⚠ RITA: falling back to raw Zeek logs ({len(csv_text)} chars)")

            csv_path = OUTPUTS_DIR / f"{name}.csv"
            csv_path.write_text(csv_text, encoding="utf-8")

            # LSTM requires iat_oresp_* feature columns; try exporting from RITA DB first.
            yield sse_event("step", "lstm")
            lstm_results = None
            if _LSTM_AVAILABLE and rita_ok:
                lstm_csv_text = csv_text
                try:
                    exported = export_lstm_feature_csv_from_rita_db(rita_db_name)
                    if exported.strip():
                        lstm_csv_text = exported
                        print("✓ LSTM: using RITA DB feature export (iat_oresp_*)")
                    else:
                        print("⚠ LSTM: empty RITA DB feature export, fallback to RITA view output")
                except Exception as e:
                    print(f"⚠ LSTM: feature export failed, fallback to RITA view output — {e}")
                lstm_results = predict_beacons(lstm_csv_text)

            # RAG attribution — search MITRE ATT&CK knowledge base for matching APT groups
            yield sse_event("step", "rag")
            rag_context = None
            if not _RAG_AVAILABLE:
                print("⏭ RAG: skipped (dependencies not installed: chromadb or sentence-transformers)")
            elif not rita_ok:
                print("⏭ RAG: skipped (RITA unavailable, no CSV data to extract features from)")
            else:
                try:
                    print("🔍 RAG: extracting threat features from RITA CSV + Zeek logs...")
                    extractor = ThreatFeatureExtractor(csv_text, output_dir)
                    features = extractor.extract_all()
                    print(f"🔍 RAG: extracted {len(features)} threat feature(s)")

                    if not features:
                        print("⏭ RAG: no high-risk threats found, skipping attribution")
                    else:
                        print("🔍 RAG: initializing knowledge base + embedding model...")
                        rag_engine = ThreatAttributionEngine(kb_path=APP_ROOT / "chroma_db")
                        print(f"🔍 RAG: searching for matching APT groups (top-{rag_engine.top_k})...")
                        rag_result = rag_engine.attribute_single_threat(features[0])

                        if rag_result["candidates"]:
                            primary = rag_result["primary_candidate"]
                            print(f"✓ RAG: matched! primary={primary['name']}, "
                                  f"confidence={rag_result['confidence']:.1f}%, "
                                  f"candidates={len(rag_result['candidates'])}")
                            rag_context = rag_engine.generate_attribution_report(rag_result)
                        else:
                            print("⚠ RAG: no matching APT group found in knowledge base")
                except Exception as e:
                    print(f"❌ RAG: failed — {e}")
                    import traceback
                    traceback.print_exc()

            yield sse_event("step", "ai")
            analysis_markdown = generate_ai_analysis(
                csv_text, lstm_results=lstm_results, rita_ok=rita_ok, rag_context=rag_context,
            )

            payload = json.dumps(
                {
                    "name": name,
                    "csv_path": str(csv_path),
                    "analysis_markdown": analysis_markdown,
                }
            )
            yield sse_event("result", payload)
        except HTTPException as exc:
            yield sse_event("error", exc.detail)

    return StreamingResponse(stream(), media_type="text/event-stream")
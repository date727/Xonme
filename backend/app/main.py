import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import requests

# LSTM beacon detection — gracefully degrades if dependencies are missing
try:
    from app.lstm_predictor import predict_beacons, format_for_prompt as _fmt_lstm

    _LSTM_AVAILABLE = True
except ImportError:
    _LSTM_AVAILABLE = False
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


def generate_ai_analysis(csv_text: str, lstm_results: dict | None = None, *, rita_ok: bool = True) -> str:
    if not SILICONFLOW_BASE_URL or not SILICONFLOW_API_KEY or not SILICONFLOW_MODEL:
        raise HTTPException(status_code=500, detail="Missing SiliconFlow API configuration")

    url = f"{SILICONFLOW_BASE_URL}/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {SILICONFLOW_API_KEY}",
        "Content-Type": "application/json",
    }

    # Build the base prompt — RITA CSV when available, raw Zeek logs otherwise
    source = "RITA CSV report" if rita_ok else "Zeek network log data"
    prompt = (
        f"You are a security analyst. Review the following {source} "
        "and summarize notable findings, risks, and recommended next steps. "
        "Return Markdown.\n\n"
    )

    # Augment with LSTM beacon detection results when available
    if lstm_results and lstm_results.get("total_flagged", 0) > 0:
        prompt += _fmt_lstm(lstm_results) + "\n\n---\n\n"

    prompt += csv_text
    payload = {
        "model": SILICONFLOW_MODEL,
        "messages": [{"role": "user", "content": prompt}],
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
        run_command(
            ["rita", "import", f"--database={name}", f"--logs={output_dir}"],
            timeout=600,
        )
    except HTTPException:
        pass  # import failed → fallback below
    else:
        try:
            view_result = subprocess.run(
                ["rita", "view", "--stdout", name],
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass  # view failed → fallback below
        else:
            csv_text = view_result.stdout
            rita_ok = True

    if not rita_ok:
        csv_text = _collect_zeek_logs(output_dir)

    csv_path = OUTPUTS_DIR / f"{name}.csv"
    csv_path.write_text(csv_text, encoding="utf-8")

    # LSTM requires RITA's iat_oresp_* columns — skip when RITA is unavailable
    lstm_results = predict_beacons(csv_text) if _LSTM_AVAILABLE and rita_ok else None

    analysis_markdown = generate_ai_analysis(csv_text, lstm_results=lstm_results, rita_ok=rita_ok)

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
                run_command(
                    ["rita", "import", f"--database={name}", f"--logs={output_dir}"],
                    timeout=600,
                )
            except HTTPException:
                pass  # import failed → fallback below
            else:
                try:
                    view_result = subprocess.run(
                        ["rita", "view", "--stdout", name],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass  # view failed → fallback below
                else:
                    csv_text = view_result.stdout
                    rita_ok = True

            if not rita_ok:
                csv_text = _collect_zeek_logs(output_dir)

            csv_path = OUTPUTS_DIR / f"{name}.csv"
            csv_path.write_text(csv_text, encoding="utf-8")

            # LSTM requires RITA's iat_oresp_* columns — skip when RITA is unavailable
            yield sse_event("step", "lstm")
            lstm_results = predict_beacons(csv_text) if _LSTM_AVAILABLE and rita_ok else None

            yield sse_event("step", "ai")
            analysis_markdown = generate_ai_analysis(csv_text, lstm_results=lstm_results, rita_ok=rita_ok)

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

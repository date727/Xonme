import os
import shutil
import subprocess
import uuid
from pathlib import Path

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
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


def run_command(cmd: list[str], cwd: Path | None = None) -> None:
    try:
        subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        detail = stderr or stdout or "Command failed"
        raise HTTPException(status_code=500, detail=detail) from exc


def generate_ai_analysis(csv_text: str) -> str:
    if not SILICONFLOW_BASE_URL or not SILICONFLOW_API_KEY or not SILICONFLOW_MODEL:
        raise HTTPException(status_code=500, detail="Missing SiliconFlow API configuration")

    url = f"{SILICONFLOW_BASE_URL}/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {SILICONFLOW_API_KEY}",
        "Content-Type": "application/json",
    }
    prompt = (
        "You are a security analyst. Review the following RITA CSV report "
        "and summarize notable findings, risks, and recommended next steps. "
        "Return Markdown.\n\n"
        f"{csv_text}"
    )
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


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_pcap(pcap: UploadFile = File(...)) -> AnalyzeResponse:
    ensure_dirs()

    name = uuid.uuid4().hex
    upload_path = UPLOADS_DIR / f"{name}.pcap"
    output_dir = OUTPUTS_DIR / name
    output_dir.mkdir(parents=True, exist_ok=True)

    with upload_path.open("wb") as f:
        shutil.copyfileobj(pcap.file, f)

    run_command(["zeek", "readpcap", str(upload_path), str(output_dir)])
    run_command(["rita", "import", f"--database={name}", f"--logs={output_dir}"])

    try:
        view_result = subprocess.run(
            ["rita", "view", "--stdout", name],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        detail = stderr or stdout or "rita view failed"
        raise HTTPException(status_code=500, detail=detail) from exc

    csv_text = view_result.stdout
    csv_path = OUTPUTS_DIR / f"{name}.csv"
    csv_path.write_text(csv_text, encoding="utf-8")

    analysis_markdown = generate_ai_analysis(csv_text)

    return AnalyzeResponse(
        name=name,
        csv_path=str(csv_path),
        analysis_markdown=analysis_markdown,
    )

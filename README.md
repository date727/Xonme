# PCAP Insight

PCAP Insight is a simple two-part project:

- Frontend: drag-and-drop PCAP upload with Markdown-rendered analysis
- Backend: Zeek + RITA processing pipeline with SiliconFlow AI analysis

## Project layout

- frontend/ - static UI
- backend/ - FastAPI service

## Backend setup

1. Ensure `zeek` and `rita` are installed and on your PATH.
2. Create a Python virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

3. Fill in the SiliconFlow settings in backend/.env:

```bash
SILICONFLOW_BASE_URL=https://api.siliconflow.cn
SILICONFLOW_API_KEY=your_key_here
SILICONFLOW_MODEL=your_model_here
```

4. Start the API server:

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8765 --reload
```

The API listens on http://127.0.0.1:8000.

## Frontend setup

You can open frontend/index.html directly, or run a local server:

```bash
cd frontend
python3 -m http.server 5500
```

Then open http://127.0.0.1:5500 in your browser.

## How it works

1. The frontend uploads a PCAP to `POST /analyze`.
2. The backend runs:
   - `zeek -r <pcap> -C LogAscii::use_json=F` (outputs TSV logs to `./outputs/<name>/`)
   - `rita import --database=<name> --logs=<output_dir>`
   - `rita view --stdout <name> > <name>.csv`
3. The LSTM beacon detection model analyzes the RITA CSV and flags suspicious connections.
4. The RITA CSV and LSTM results are sent to SiliconFlow for a Markdown summary.
5. The frontend renders the Markdown response.

## Compatibility notes

- **Zeek ≥ 5.0 / ≤ 7.x**: The backend forces TSV log output (`LogAscii::use_json=F`) because RITA cannot parse JSON-format Zeek logs.
- **RITA**: Requires Zeek TSV logs. Ensure MongoDB is running before starting the backend.
- **Python ≥ 3.10**: Required for the `dict | None` union syntax.

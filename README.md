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
uvicorn backend.app.main:app --reload
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
   - `zeek readpcap <pcap> ./outputs/<name>`
   - `rita import --database=<name> --logs=<output_dir>`
   - `rita view --stdout <name> > <name>.csv`
3. The CSV is sent to SiliconFlow for a Markdown summary.
4. The frontend renders the Markdown response.

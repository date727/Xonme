"""Loopback-only HTTP API called by the C2Sherlock web page."""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from capture_state import COORDINATOR
from config import CONFIG
from dumpcap_manager import DumpcapError
from models import CaptureStartRequest


app = FastAPI(title="C2Sherlock Collector", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(CONFIG.allowed_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Access-Control-Request-Private-Network"],
)


@app.middleware("http")
async def protect_loopback(request: Request, call_next):
    host = request.headers.get("host", "").split(":", 1)[0].strip("[]").lower()
    if host not in {"127.0.0.1", "localhost"}:
        return _error(403, "本地采集器只接受回环地址请求")
    origin = request.headers.get("origin")
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and origin not in CONFIG.allowed_origins:
        return _error(403, "网页来源不在采集器白名单中")
    response = await call_next(request)
    if request.headers.get("access-control-request-private-network") == "true":
        response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


def _error(status_code: int, detail: str):
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=status_code, content={"detail": detail})


@app.get("/status")
def status(refresh: bool = False) -> dict:
    if refresh:
        COORDINATOR.environment(force=True)
    return COORDINATOR.status()


@app.get("/interfaces")
def interfaces() -> dict:
    try:
        return {"interfaces": COORDINATOR.interfaces()}
    except DumpcapError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/start", status_code=201)
def start(payload: CaptureStartRequest) -> dict:
    try:
        return COORDINATOR.start(payload)
    except DumpcapError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/stop")
def stop() -> dict:
    try:
        return COORDINATOR.stop()
    except DumpcapError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.on_event("shutdown")
def shutdown() -> None:
    COORDINATOR.shutdown()

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from ui.web.state import web_state
from ui.web.runner import run_scan
from core.report.html import HTMLReport
from collections import Counter
import threading
from pathlib import Path
import asyncio
from core.ai.prompt import build_prompt
from core.ai.offline import OfflineAIAdvisor
from core.ai.llm_loader import load_llm
from core.ai.cache import AICache

app = FastAPI()
BASE_DIR = Path(__file__).resolve().parent

active_connections: list[WebSocket] = []

@app.get("/", response_class=HTMLResponse)
def index():
    return (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")

# Thread Tracking
scan_thread = None

# WebSocket Endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)

    try:
        while True:
            await send_status_update(websocket)
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        active_connections.remove(websocket)


async def send_status_update(websocket: WebSocket):
    type_dist = Counter(v.vuln_type for v in web_state.vulnerabilities)
    severity_dist = Counter(getattr(v, "severity", "medium") for v in web_state.vulnerabilities)

    threat_index = (
        severity_dist.get("critical", 0) * 4 +
        severity_dist.get("high", 0) * 3 +
        severity_dist.get("medium", 0) * 2 +
        severity_dist.get("low", 0) * 1
    )

    await websocket.send_json({
        "phase": web_state.phase,
        "urls": web_state.discovered_urls,
        "vulns": [
            {
                "type": v.vuln_type,
                "url": v.url,
                "param": v.parameter,
                "ai": getattr(v, "ai_fix", None),
                "severity": getattr(v, "severity", "medium"),
            }
            for v in web_state.vulnerabilities
        ],
        "analytics": {
            "type_distribution": type_dist,
            "severity_distribution": severity_dist,
            "threat_index": threat_index
        },
        "elapsed": getattr(web_state, "elapsed", 0),
    })


# Scan Control
def reset_state(state):
    state.phase = "idle"
    state.stop = False
    state.paused = False
    state.stopped = False
    state.ai_done = False
    state.elapsed = 0
    state.discovered_urls.clear()
    state.vulnerabilities.clear()


@app.post("/start")
def start(target: str, url_limit: int = 25, ai_limit: int = 2):
    global scan_thread

    if scan_thread and scan_thread.is_alive():
        return {"status": "scan already running"}

    reset_state(web_state)

    scan_thread = threading.Thread(
        target=run_scan,
        args=(web_state, target, url_limit, ai_limit),
        daemon=True
    )
    scan_thread.start()

    return {"status": "started"}


@app.post("/stop")
def stop_scan():
    web_state.paused = True
    web_state.phase = "paused"
    return {"status": "paused"}


@app.post("/resume")
def resume_scan():
    web_state.paused = False
    web_state.phase = "scanning"
    return {"status": "resumed"}


@app.post("/reset")
def reset_scan():
    global scan_thread

    web_state.stop = True
    web_state.paused = False

    # Wait for scan thread to terminate
    if scan_thread and scan_thread.is_alive():
        scan_thread.join(timeout=2)

    reset_state(web_state)

    return {"status": "reset"}


@app.post("/generate_ai")
def generate_ai(selected_ids: list[int]):
    if not web_state.vulnerabilities:
        return {"status": "no vulnerabilities"}

    llm = load_llm("models/mistral-7b-instruct-v0.1.Q4_K_M.gguf")
    ai = OfflineAIAdvisor(llm)
    cache = AICache()

    for idx in selected_ids:
        if idx < len(web_state.vulnerabilities):
            v = web_state.vulnerabilities[idx]
            prompt = build_prompt(v)
            v.ai_fix = cache.get(prompt) or ai.generate_fix(prompt)
            cache.set(prompt, v.ai_fix)

    return {"status": "done"}


@app.post("/generate_ai")
def generate_ai(selected_ids: list[int]):
    total_tokens = 0

    llm = load_llm("models/mistral-7b-instruct-v0.1.Q4_K_M.gguf")
    ai = OfflineAIAdvisor(llm)
    cache = AICache()

    for idx in selected_ids:
        if idx < len(web_state.vulnerabilities):
            v = web_state.vulnerabilities[idx]
            prompt = build_prompt(v)

            cached = cache.get(prompt)
            if cached:
                v.ai_fix = cached
            else:
                result = ai.generate_fix(prompt)
                v.ai_fix = result
                cache.set(prompt, result)

                # approximate token usage
                total_tokens += len(prompt.split()) + len(result.split())

    return {"status":"done","tokens":total_tokens}


@app.get("/report/html")
def download_html_report():
    report = HTMLReport()
    path = report.generate(web_state)
    return FileResponse(
        path,
        filename="vulscanware_report.html",
        media_type="text/html"
    )
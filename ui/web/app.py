from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, FileResponse
from ui.web.state import web_state
from ui.web.runner import run_scan
from core.report.html import HTMLReport
import threading
from pathlib import Path
import asyncio
from core.ai.prompt import build_prompt
from core.ai.offline import OfflineAIAdvisor
from core.ai.llm_loader import load_llm
from core.ai.cache import AICache
import time
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI()
BASE_DIR = Path(__file__).resolve().parent
active_connections: list[WebSocket] = []

# Mount static files (CSS, JS)
app.mount("/static", StaticFiles(directory="ui/web/static"), name="static")

# Setup templates
templates = Jinja2Templates(directory="ui/web/templates")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


scan_thread = None


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
    type_dist = {}
    severity_dist = {}

    for v in web_state.vulnerabilities:
        # ---- TYPE DISTRIBUTION ----
        t = getattr(v, "vuln_type", None)

        if not t:
            t = "Unknown"

        if t not in type_dist:
            type_dist[t] = 0

        type_dist[t] += 1

        # ---- SEVERITY DISTRIBUTION ----
        s = getattr(v, "severity", "low")

        if s not in severity_dist:
            severity_dist[s] = 0

        severity_dist[s] += 1

    def calculate_threat_index(vulns):
        weights = {
            "critical": 10,
            "high": 6,
            "medium": 3,
            "low": 1
        }
        seen = set()
        score = 0

        from urllib.parse import urlparse
        for v in vulns:

            endpoint = urlparse(v.url).path
            param = (v.parameter or "").lower()
            key = (endpoint, param, v.vuln_type)

            if key in seen:
                continue

            seen.add(key)
            severity = (v.severity or "low").lower()
            score += weights.get(severity, 1)
        return min(score, 100)

    def calculate_attack_surface(vulns, urls):
        from urllib.parse import urlparse
        seen = set()

        for v in vulns:
            endpoint = urlparse(v.url).path
            param = (v.parameter or "").lower()
            key = (endpoint, param, v.vuln_type)
            seen.add(key)

        unique_vulns = len(seen)
        pages = max(len(urls), 1)
        score = round(unique_vulns / pages, 2)
        return score

    await websocket.send_json({
        "phase": web_state.phase,
        "urls": web_state.discovered_urls,
        "vulns": [
            {
                "vuln_type": v.vuln_type,
                "type": v.vuln_type,
                "url": v.url,
                "param": v.parameter,
                "ai_fix": getattr(v, "ai_fix", None),
                "ai_prompt": getattr(v, "ai_prompt", None),
                "severity": getattr(v, "severity", None),
                "context": getattr(v, "context", None),
                "ai_time": getattr(v, "ai_time", None),
            }
            for v in web_state.vulnerabilities
        ],
        "analytics": {
            "type_distribution": type_dist,
            "severity_distribution": severity_dist,
            "threat_index": calculate_threat_index(web_state.vulnerabilities),
            "attack_surface": calculate_attack_surface(
                web_state.vulnerabilities,
                web_state.discovered_urls
            )
        },
        "elapsed": getattr(web_state, "elapsed", 0),
    })


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
def start(target: str, url_limit: int = 25, depth_limit: int = 2):
    global scan_thread

    if scan_thread and scan_thread.is_alive():
        return {"status": "scan already running"}

    reset_state(web_state)
    scan_thread = threading.Thread(
        target=run_scan,
        args=(web_state, target, url_limit, depth_limit),
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
    total_tokens = 0
    llm = load_llm("models/mistral-7b-instruct-v0.1.Q4_K_M.gguf")
    ai = OfflineAIAdvisor(llm)
    cache = AICache()

    for idx in selected_ids:
        if idx >= len(web_state.vulnerabilities):
            continue

        v = web_state.vulnerabilities[idx]
        prompt = build_prompt(v)
        cached = cache.get(v)

        if cached:
            response_text = cached
            duration = "⚡ Cached result"
        else:
            start = time.time()
            response_text = ai.generate_fix(prompt)
            duration = round(time.time() - start, 2)
            cache.set(v, response_text)
        v.ai_fix = response_text
        v.ai_time = duration
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
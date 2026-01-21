from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from ui.web.state import web_state
from ui.web.runner import run_scan
import threading
from pathlib import Path
from core.report.html import HTMLReport


app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent

@app.get("/", response_class=HTMLResponse)
def index():
    return (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")

def reset_state(state):
    state.phase = "idle"
    state.stop = False
    state.ai_done = False
    state.elapsed = None
    state.discovered_urls.clear()
    state.vulnerabilities.clear()


@app.post("/start")
def start(target: str, url_limit: int = 25, ai_limit: int = 2):
    reset_state(web_state)
    web_state.phase = "starting"
    web_state.stop = False
    web_state.discovered_urls.clear()
    web_state.vulnerabilities.clear()
    web_state.ai_done = False
    t = threading.Thread(
        target=run_scan,
        args=(web_state, target, url_limit, ai_limit),
        daemon=True,
    )
    t.start()

    return {"status": "started"}

@app.get("/status")
def status():
    return JSONResponse({
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
        "summary": {
            "urls_crawled": len(web_state.discovered_urls),
            "vulns_found": len(web_state.vulnerabilities),
            "ai_done": web_state.ai_done,
            "time_taken": getattr(web_state, "elapsed", None),
        }
    })

@app.post("/stop")
def stop():
    web_state.stop = True
    return {"status": "stopping"}

@app.get("/report/html")
def download_html_report():
    report = HTMLReport()
    path = report.generate(web_state)
    return FileResponse(
        path,
        filename="vulscanware_report.html",
        media_type="text/html"
    )



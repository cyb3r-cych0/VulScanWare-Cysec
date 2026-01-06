from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from engine import ScanEngine

app = FastAPI(title="VulScanWare Web")
templates = Jinja2Templates(directory="ui/web/templates")

# ---------- API ----------
class ScanRequest(BaseModel):
    target: str

@app.post("/api/scan")
def api_scan(req: ScanRequest):
    engine = ScanEngine()
    return engine.run(req.target)

# ---------- WEB ----------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html"
    )

@app.post("/scan", response_class=HTMLResponse)
def web_scan(request: Request, target: str = Form(...), dom: bool = Form(False)):
    engine = ScanEngine(dom=dom)
    result = engine.run(target)

    return templates.TemplateResponse(
        request,
        "results.html",
        {"result": result}
    )

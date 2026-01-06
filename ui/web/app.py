from fastapi import FastAPI
from pydantic import BaseModel
from engine import ScanEngine

app = FastAPI(title="VulScanWare")

class ScanRequest(BaseModel):
    target: str
    offline: bool = True

@app.post("/scan")
def start_scan(req: ScanRequest):
    engine = ScanEngine()
    result = engine.run(req.target)
    return result

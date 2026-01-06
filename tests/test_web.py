"""verify page loads — not HTML content."""
from fastapi.testclient import TestClient
from ui.web.app import app

client = TestClient(app)

def test_scan_endpoint():
    r = client.post("/api/scan", json={"target": "http://example.com"})
    assert r.status_code == 200
    assert "target" in r.json()

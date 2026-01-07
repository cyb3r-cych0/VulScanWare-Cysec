"""verify page loads — not HTML content."""
from fastapi.testclient import TestClient
from ui.web.app import app

client = TestClient(app)

def test_scan_endpoint():
    r = client.post(
        "/start",
        params={
            "target": "http://example.com",
            "url_limit": 5,
            "ai_limit": 0,
        },
    )
    assert r.status_code == 200

def test_status_endpoint():
    r = client.get("/status")
    assert r.status_code == 200
    assert "phase" in r.json()

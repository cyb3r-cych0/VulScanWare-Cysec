"""
    API boots
    Schema is serializable
    Engine integration works
"""
from fastapi.testclient import TestClient
from ui.web.app import app

client = TestClient(app)

def test_scan_endpoint():
    response = client.post("/scan", json={
        "target": "http://test",
        "offline": True
    })
    assert response.status_code == 200
    assert "target" in response.json()

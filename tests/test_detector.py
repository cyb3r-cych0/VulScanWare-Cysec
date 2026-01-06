from core.detector.reflected import ReflectedXSSDetector

class FakeResponse:
    text = "hello <script>alert(1)</script> world"

def fake_get(url, timeout):
    return FakeResponse()

def test_reflected_xss_detected(monkeypatch):
    import requests
    monkeypatch.setattr(requests, "get", fake_get)

    detector = ReflectedXSSDetector()

    injection = {
        "url": "http://example.com/?q=test",
        "method": "GET",
        "parameter": "q",
        "payload": "<script>alert(1)</script>"
    }

    vuln = detector.detect(injection)

    assert vuln is not None
    assert vuln.vuln_type == "Reflected XSS"

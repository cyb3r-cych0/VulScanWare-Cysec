from core.detector.reflected import ReflectedXSSDetector
import requests


def test_reflected_xss_detection(monkeypatch):
    detector = ReflectedXSSDetector()
    injection = {
        "url": "http://example.com/?q=<script>alert(1)</script>",
        "method": "GET",
        "parameter": "q",
        "payload": "<script>alert(1)</script>"
    }

    class MockResponse:
        text = "<html><script>alert(1)</script></html>"

    # mock requests.get
    def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(requests, "get", mock_get)
    result = detector.detect(injection)

    assert result is not None
    assert result.vuln_type == "Reflected XSS"
from core.engine import ScanEngine
import requests


def test_full_scan_pipeline(monkeypatch):
    # ---- Mock HTTP response ----
    class MockResponse:
        text = "<html><script>alert('VSW_TEST')</script></html>"
        headers = {"Content-Type": "text/html"}

    def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(requests, "get", mock_get)

    # ---- Mock crawler ----
    class MockCrawler:
        def crawl(self, target):
            return ["http://example.com/?q=test"]

    engine = ScanEngine(
        crawler=MockCrawler(),
        url_limit=1,
        depth_limit=1
    )

    result = engine.run("http://example.com")

    assert result is not None
    assert isinstance(result.vulnerabilities, list)
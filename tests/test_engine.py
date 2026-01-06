"""
    Orchestration logic
    No UI coupling
    Deterministic behavior
"""
from engine import ScanEngine
from core.models import Vulnerability

class FakeCrawler:
    def crawl(self, target):
        return ["http://test/?q=1"]

class FakeInjector:
    def inject(self, url):
        return [{"url": url, "payload": "<script>"}]

class FakeDetector:
    def detect(self, injection):
        return Vulnerability(
            vuln_type="Reflected XSS",
            url=injection["url"],
            parameter="q",
            method="GET",
            payload=injection["payload"],
            evidence="reflected"
        )

def test_scan_engine_flow():
    engine = ScanEngine(
        crawler=FakeCrawler(),
        injector=FakeInjector(),
        detector=FakeDetector()
    )

    result = engine.run("http://test")

    assert result.scanned_urls == 1
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].vuln_type == "Reflected XSS"

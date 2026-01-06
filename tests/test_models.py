"""Confirms contracts are stable"""
from core.models import Vulnerability, ScanResult

def test_vulnerability_model():
    v = Vulnerability(
        vuln_type="Reflected XSS",
        url="http://test",
        parameter="q",
        method="GET",
        payload="<script>",
        evidence="reflected"
    )
    assert v.vuln_type == "Reflected XSS"
    assert v.severity == "high"

def test_scan_result_model():
    result = ScanResult(
        target="http://test",
        vulnerabilities=[],
        scanned_urls=5
    )
    assert result.scanned_urls == 5

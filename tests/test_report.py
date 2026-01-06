from core.report.html import HTMLReport
from core.models import ScanResult

def test_html_report_generation(tmp_path):
    result = ScanResult("http://x", [], 0)
    out = tmp_path / "r.html"

    path = HTMLReport().generate(result, out_file=out)
    assert out.exists()

from core.report.json_report import JSONReport
from core.models import ScanResult

def test_json_ci_report(tmp_path):
    r = ScanResult("x", [], 0)
    out = tmp_path / "r.json"
    JSONReport().generate(r, out_file=out)
    assert out.exists()

from core.engine import ScanEngine


def test_scan_engine_runs():
    engine = ScanEngine(url_limit=1, depth_limit=1)
    result = engine.run("http://example.com")

    assert result is not None
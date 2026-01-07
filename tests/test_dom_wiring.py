def test_dom_flag_does_not_break_engine():
    from core.engine import ScanEngine
    engine = ScanEngine(dom=True)
    # no exception on run with empty crawl
    res = engine.run("http://example.com")
    assert hasattr(res, "scanned_urls")

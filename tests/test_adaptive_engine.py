from core.payloads.adaptive import AdaptiveEngine

def test_adaptive_engine():

    engine = AdaptiveEngine()

    result = engine.analyze("<html>alert(1)</html>", "alert(1)")

    assert result in ["reflected", "filtered", "encoded"]
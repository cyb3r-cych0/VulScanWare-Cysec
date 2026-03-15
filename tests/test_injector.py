from core.injector.basic import BasicInjector


def test_injector_generates_payloads():
    injector = BasicInjector()
    injections = injector.inject("http://example.com/?q=test")

    assert len(injections) > 0
    assert "payload" in injections[0]
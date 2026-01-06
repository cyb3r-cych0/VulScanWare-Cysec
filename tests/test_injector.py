from core.injector.basic import BasicInjector

class FakeResponse:
    headers = {"Content-Type": "text/html"}
    text = """
    <form action="/submit" method="post">
        <input name="username">
        <input name="password">
    </form>
    """

def fake_get(url, timeout):
    return FakeResponse()

def test_injector_generates_get_and_form_payloads(monkeypatch):
    import requests
    monkeypatch.setattr(requests, "get", fake_get)

    injector = BasicInjector()
    injections = injector.inject("http://example.com/?q=1")

    assert any(i["method"] == "GET" for i in injections)
    assert any(i["method"] == "POST" for i in injections)

    # payloads now come from registry
    assert any("payload" in i for i in injections)

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

    injector = BasicInjector(payloads=["XSS"])
    injections = injector.inject("http://example.com/?q=1")

    # GET injection
    assert any(i["method"] == "GET" for i in injections)

    # FORM injection
    assert any(i["method"] == "POST" for i in injections)

    # Payload present
    assert any(i["payload"] == "XSS" for i in injections)

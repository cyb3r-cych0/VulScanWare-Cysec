from core.payloads.registry import get_payloads

def test_payload_registry_context():

    html_payloads = get_payloads("html")

    assert len(html_payloads) > 0

    for p in html_payloads:
        assert p["context"] == "html"
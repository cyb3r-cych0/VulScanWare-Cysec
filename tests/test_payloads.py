from core.payloads.registry import get_payloads

def test_payload_generation():
    payloads = get_payloads()

    values = [p["payload"] for p in payloads]

    assert "<script>alert(1)</script>" in values
    assert "%3Cscript%3Ealert%281%29%3C/script%3E" in values

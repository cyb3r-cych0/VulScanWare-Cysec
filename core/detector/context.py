import re


def find_context(payload: str, response_text: str):

    contexts = []

    # HTML body context
    if payload in response_text:
        contexts.append("html")

    # attribute context
    attr_pattern = r'=\s*["\']?[^"\'>]*' + re.escape(payload)
    if re.search(attr_pattern, response_text, re.IGNORECASE):
        contexts.append("attribute")

    # javascript context
    script_pattern = r"<script[^>]*>.*?" + re.escape(payload)
    if re.search(script_pattern, response_text, re.IGNORECASE | re.DOTALL):
        contexts.append("javascript")

    # URL context
    url_pattern = r'href\s*=\s*["\']?[^"\'>]*' + re.escape(payload)
    if re.search(url_pattern, response_text, re.IGNORECASE):
        contexts.append("url")

    return list(set(contexts))
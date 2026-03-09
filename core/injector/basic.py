from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import requests
from bs4 import BeautifulSoup
from core.payloads.registry import get_payloads
from core.payloads.mutator import mutate
from core.debug.payload_logger import log_injection


# Context Detection
def detect_context(input_tag):
    tag = input_tag.name

    if tag == "textarea":
        return "html"

    if tag == "input":
        t = input_tag.get("type", "text")

        if t in ["url"]:
            return "url"

        if t in ["search", "text", "email"]:
            return "html"

        if t in ["hidden"]:
            return None

    return "html"


class BasicInjector:

    def __init__(self, timeout=5):
        self.timeout = timeout

    def inject(self, url: str):

        injections = []

        # ----------------------------
        # GET PARAMETER INJECTION
        # ----------------------------
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param in params:

            # URL parameters are usually html/url contexts
            for payload_obj in get_payloads("html") + get_payloads("url"):

                base_payload = payload_obj["payload"]

                for payload in mutate(base_payload):
                    new_params = params.copy()
                    new_params[param] = payload

                    new_query = urlencode(new_params, doseq=True)

                    new_url = urlunparse(
                        parsed._replace(query=new_query)
                    )

                    log_injection("GET", new_url, param, payload)

                    injections.append({
                        "url": new_url,
                        "method": "GET",
                        "parameter": param,
                        "payload": payload
                    })

        # ----------------------------
        # FORM INJECTION
        # ----------------------------
        try:
            r = requests.get(url, timeout=self.timeout)

            if "text/html" not in r.headers.get("Content-Type", ""):
                return injections

        except requests.RequestException:
            return injections

        soup = BeautifulSoup(r.text, "html.parser")

        forms = soup.find_all("form")

        for form in forms:

            action = urljoin(url, form.get("action") or "")
            method = form.get("method", "get").upper()

            inputs = form.find_all(["input", "textarea", "select"])

            form_defaults = {}

            for i in inputs:
                name = i.get("name")
                if not name:
                    continue

                value = i.get("value")

                if value is None:
                    value = "test"

                form_defaults[name] = value

            fields = []

            for i in inputs:
                name = i.get("name")
                if name:
                    fields.append(name)

            if not fields:
                continue

            for i in inputs:

                field = i.get("name")
                if not field:
                    continue

                context = detect_context(i)

                # skip hidden fields
                if context is None:
                    continue

                for payload_obj in get_payloads(context):

                    base_payload = payload_obj["payload"]

                    for payload in mutate(base_payload):
                        data = form_defaults.copy()

                        # inject payload into target field
                        data[field] = payload

                        log_injection(method, action, field, payload, data)

                        injections.append({
                            "url": action,
                            "method": method,
                            "parameter": field,
                            "payload": payload,
                            "data": data
                        })

        return injections
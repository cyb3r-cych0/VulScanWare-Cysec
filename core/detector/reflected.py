import requests
from core.models import Vulnerability

class ReflectedXSSDetector:
    def __init__(self, timeout=5):
        self.timeout = timeout

    def detect(self, injection: dict):
        try:
            if injection["method"] == "GET":
                r = requests.get(
                    injection["url"],
                    timeout=self.timeout
                )
            else:
                r = requests.post(
                    injection["url"],
                    data=injection.get("data", {}),
                    timeout=self.timeout
                )
        except requests.RequestException:
            return None

        payload = injection["payload"]

        if payload in r.text:
            return Vulnerability(
                vuln_type="Reflected XSS",
                url=injection["url"],
                parameter=injection["parameter"],
                method=injection["method"],
                payload=payload,
                evidence="Payload reflected in response body",
                severity="high"
            )

        return None

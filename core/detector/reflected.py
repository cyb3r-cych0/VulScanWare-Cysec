import requests
from core.models import Vulnerability
from core.detector.context import find_context
from core.scoring.severity import score_vulnerability


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

        # ---- context analysis ----
        contexts = find_context(payload, r.text)

        if not contexts:
            return None

        # ---- severity mapping ----
        severity = score_vulnerability(contexts, payload)

        return Vulnerability(
            vuln_type="Reflected XSS",
            url=injection["url"],
            parameter=injection["parameter"],
            method=injection["method"],
            payload=payload,
            evidence=f"Payload reflected in contexts: {', '.join(contexts)}",
            severity=severity
        )
import requests
from core.models import Vulnerability
from core.detector.context import find_context
from core.scoring.severity import score_vulnerability
from core.analysis.context_analyzer import ReflectionContextAnalyzer


class ReflectedXSSDetector:

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.context_analyzer = ReflectionContextAnalyzer()

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

        # dominant context
        context = contexts[0]

        # deeper context analysis
        extra_context = self.context_analyzer.analyze(r.text, payload)

        if extra_context and extra_context not in contexts:
            context = extra_context

        # ---- severity mapping ----
        severity = score_vulnerability(context, payload)

        return Vulnerability(
            vuln_type="Reflected XSS",
            url=injection["url"],
            parameter=injection["parameter"],
            method=injection["method"],
            payload=payload,
            evidence=f"Payload reflected in {context} context",
            severity=severity,
            context=context
        )
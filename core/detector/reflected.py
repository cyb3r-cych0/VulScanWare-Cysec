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
        contexts = find_context( # context analysis
            payload, r.text
        )
        if not contexts:
            return None
        context = contexts[0] # dominant context
        extra_context = self.context_analyzer.analyze( # deeper context analysis
            r.text, payload
        )
        if extra_context and extra_context not in contexts:
            context = extra_context
        severity = score_vulnerability( # severity mapping
            context, payload
        )
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
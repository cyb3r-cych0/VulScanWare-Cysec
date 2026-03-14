import requests
import re
from core.models import Vulnerability


class StoredXSSTracker:

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.tracked_payloads = []
        self.detected_urls = set()   # prevents duplicate stored findings

    def track(self, injection):

        payload = injection["payload"]

        # extract fingerprint token if present
        match = re.search(r"VSW_[A-Z0-9]+", payload)

        token = match.group(0) if match else payload

        entry = {
            "token": token,
            "parameter": injection.get("parameter") or injection.get("param"),
            "url": injection["url"]
        }

        if entry not in self.tracked_payloads:
            self.tracked_payloads.append(entry)

    def check_pages(self, urls):

        findings = []

        for url in urls:

            try:
                r = requests.get(url, timeout=self.timeout)
            except requests.RequestException:
                continue

            for entry in self.tracked_payloads:
                token = entry["token"]

                if token in r.text:
                    # prevent duplicate reporting
                    if (url, token) in self.detected_urls:
                        continue

                    self.detected_urls.add((url, token))

                    findings.append(
                        Vulnerability(
                            vuln_type="Stored XSS",
                            url=url,
                            parameter=entry["parameter"],
                            method="GET",
                            payload=token,
                            evidence=f"Stored payload XSS token detected on page {url}",
                            severity="critical",
                            context="html"
                        )
                    )

        return findings
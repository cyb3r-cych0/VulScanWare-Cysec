import json

class JSONReport:
    def generate(self, scan_result, out_file="report.json"):
        data = {
            "target": scan_result.target,
            "scanned_urls": scan_result.scanned_urls,
            "findings": [
                {
                    "type": v.vuln_type,
                    "url": v.url,
                    "method": v.method,
                    "parameter": v.parameter,
                    "payload": v.payload,
                    "severity": v.severity,
                    "evidence": v.evidence,
                    "ai_fix": v.ai_fix,
                }
                for v in scan_result.vulnerabilities
            ],
        }

        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return out_file

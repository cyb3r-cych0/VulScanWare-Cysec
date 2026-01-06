import json
import uuid

class SARIFReport:
    def generate(self, scan_result, out_file="report.sarif"):
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VulScanWare",
                        "rules": []
                    }
                },
                "results": []
            }]
        }

        for v in scan_result.vulnerabilities:
            sarif["runs"][0]["results"].append({
                "ruleId": v.vuln_type,
                "level": "error",
                "message": {"text": v.evidence},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": v.url
                        }
                    }
                }]
            })

        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)

        return out_file

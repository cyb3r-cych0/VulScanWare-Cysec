def build_prompt(vuln):
    return {
        "vuln_type": vuln.vuln_type,
        "method": vuln.method,
        "parameter": vuln.parameter,
        "payload": vuln.payload,
        "evidence": vuln.evidence,
        "task": "Explain the issue and give secure remediation steps."
    }

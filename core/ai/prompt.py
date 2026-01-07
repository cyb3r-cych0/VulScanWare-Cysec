def build_prompt(vuln):
    return f"""
            You are a secure coding expert.
            
            Vulnerability type: {vuln.vuln_type}
            HTTP method: {vuln.method}
            Parameter: {vuln.parameter}
            Payload: {vuln.payload}
            
            Explain why this is dangerous and give concise remediation steps.
            """

def build_prompt(v):
    return f"""
            You are a senior application security engineer.
            
            Analyze the following Cross-Site Scripting (XSS) vulnerability and produce a structured remediation report.
            
            Vulnerability Details:
            URL: {v.url}
            Parameter: {v.parameter}
            Payload: {v.payload}
            Type: {v.vuln_type}
            
            Return your answer using EXACTLY the following sections:
            
            ### Explanation
            Explain why this vulnerability is dangerous.
            
            ### Impact
            Describe what an attacker could do.
            
            ### Secure Fix
            Provide specific remediation steps.
            
            ### Secure Code Example
            Show a short secure coding example if applicable.
            
            ### Prevention Checklist
            Provide 3–5 best practices developers should implement.
            
            Keep the response concise and security-focused.
            """

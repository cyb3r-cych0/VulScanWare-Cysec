from jinja2 import Template
from datetime import datetime

class HTMLReport:
    def generate(self, state, out_file="vulscanware_report.html"):
        template = Template("""
                    <!DOCTYPE html>
                    <html>
                    <head>
                    <meta charset="UTF-8">
                    <title>VulScanWare Report</title>
                    <style>
                    body { font-family: Arial, sans-serif; background:#0f172a; color:#e5e7eb; }
                    h1, h2 { color:#93c5fd; }
                    table { border-collapse: collapse; width:100%; margin-top:12px; }
                    th, td { border:1px solid #334155; padding:8px; }
                    th { background:#020617; }
                    .sev-high { color:#ef4444; font-weight:bold; }
                    .sev-medium { color:#facc15; }
                    .sev-low { color:#22c55e; }
                    pre { white-space: pre-wrap; }
                    </style>
                    </head>
                    <body>
                    
                    <h1>VulScanWare Scan Report</h1>
                    <p><b>Generated:</b> {{ timestamp }}</p>
                    <p><b>Phase:</b> {{ state.phase }}</p>
                    
                    <h2>Summary</h2>
                    <ul>
                      <li>URLs Crawled: {{ state.discovered_urls | length }}</li>
                      <li>Vulnerabilities Found: {{ state.vulnerabilities | length }}</li>
                      <li>AI Remediations: {{ ai_count }}</li>
                      <li>Time Taken: {{ state.elapsed }}s</li>
                    </ul>
                    
                    <h2>Vulnerabilities</h2>
                    <table>
                    <tr>
                      <th>Type</th>
                      <th>Parameter</th>
                      <th>Severity</th>
                      <th>AI Remediation</th>
                    </tr>
                    {% for v in state.vulnerabilities %}
                    <tr>
                      <td>{{ v.vuln_type }}</td>
                      <td>{{ v.parameter }} - {{ v.url }} </td>
                      <td class="sev-{{ v.severity }}">{{ v.severity }}</td>
                      <td><pre>{{ v.ai_fix or "—" }}</pre></td>
                    </tr>
                    {% endfor %}
                    </table>
                    
                    </body>
                    </html>
                    """)

        html = template.render(
            state=state,
            ai_count=len([v for v in state.vulnerabilities if getattr(v, "ai_fix", None)]),
            timestamp=datetime.now().isoformat()
        )

        with open(out_file, "w", encoding="utf-8") as f:
            f.write(html)

        return out_file

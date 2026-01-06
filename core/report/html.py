from jinja2 import Template

def generate_html(scan_result):
    template = Template("""
    <h1>VulScanWare Report</h1>
    <p>Target: {{ target }}</p>
    {% for v in vulns %}
      <div>
        <b>{{ v.vuln_type }}</b><br>
        URL: {{ v.url }}<br>
        Payload: {{ v.payload }}
      </div>
    {% endfor %}
    """)
    return template.render(
        target=scan_result.target,
        vulns=scan_result.vulnerabilities
    )

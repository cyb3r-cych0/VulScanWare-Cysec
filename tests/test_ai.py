from core.ai.base import AIAdvisor
from core.models import Vulnerability

class FakeAI(AIAdvisor):
    def generate_fix(self, context):
        return "Escape output and use CSP."

def test_ai_integration():
    vuln = Vulnerability(
        vuln_type="Reflected XSS",
        url="http://x",
        parameter="q",
        method="GET",
        payload="<script>",
        evidence="reflected"
    )

    ai = FakeAI()
    fix = ai.generate_fix({"vuln": "xss"})

    assert "Escape" in fix

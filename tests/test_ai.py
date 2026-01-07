from core.ai.offline import OfflineAIAdvisor
from core.ai.prompt import build_prompt
from core.models import Vulnerability

class FakeLLM:
    def __call__(self, prompt, **kwargs):
        return {
            "choices": [
                {"text": "Escape output and validate input."}
            ]
        }

def test_offline_ai_generates_fix():
    vuln = Vulnerability(
        vuln_type="Reflected XSS",
        url="http://test/search.php",
        parameter="q",
        method="GET",
        payload="<script>alert(1)</script>",
        evidence="Payload reflected",
    )

    llm = FakeLLM()
    ai = OfflineAIAdvisor(llm)

    prompt = build_prompt(vuln)
    fix = ai.generate_fix(prompt)

    assert "Escape" in fix

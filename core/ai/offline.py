from core.ai.base import AIAdvisor

class OfflineAIAdvisor(AIAdvisor):
    def __init__(self, llm):
        self.llm = llm  # injected llama-cpp model

    def generate_fix(self, context: dict) -> str:
        prompt = (
            "You are a secure coding assistant.\n"
            f"Vulnerability details:\n{context}\n\n"
            "Provide remediation steps."
        )
        return self.llm(prompt, max_tokens=200)

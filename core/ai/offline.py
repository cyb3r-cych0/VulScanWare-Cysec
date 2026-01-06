from core.ai.base import AIAdvisor

class OfflineAIAdvisor(AIAdvisor):
    def __init__(self, llm):
        self.llm = llm

    def generate_fix(self, context: dict) -> str:
        prompt = (
            "You are a secure coding expert.\n"
            "Explain the vulnerability and give concise remediation steps.\n\n"
            f"{context}\n"
        )

        out = self.llm(
            prompt,
            max_tokens=180,
            temperature=0.0,
            top_p=1.0,
            repeat_penalty=1.1,
            stop=["</s>"],
        )
        return out["choices"][0]["text"].strip()

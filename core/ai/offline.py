class OfflineAIAdvisor:
    def __init__(self, llm):
        self.llm = llm

    def generate_fix(self, prompt: str) -> str:
        result = self.llm(
            prompt,
            max_tokens=420,
            temperature=0.0,
            top_p=1.0,
        )
        return result["choices"][0]["text"].strip()

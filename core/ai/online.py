from core.ai.base import AIAdvisor
import openai


class OnlineAIAdvisor(AIAdvisor):
    def __init__(self, model="gpt-3.5-turbo"):
        self.model = model

    def generate_fix(self, context: dict) -> str:
        resp = openai.ChatCompletion.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are a secure coding expert."},
                {"role": "user", "content": str(context)}
            ],
            max_tokens=420
        )
        return resp.choices[0].message.content

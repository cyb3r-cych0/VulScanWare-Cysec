class AdaptiveEngine:

    def __init__(self):
        self.history = {}

    def analyze(self, response_text, payload):

        # detect common filtering
        if "<script>" not in response_text and "&lt;script&gt;" in response_text:
            return "html_escaped"

        if payload.lower() not in response_text.lower():
            return "filtered"

        return "reflected"

    def mutate(self, payload, result):

        if result == "html_escaped":
            return payload.replace("<script>", "<svg/onload=")

        if result == "filtered":
            return payload.replace("alert", "confirm")

        return payload
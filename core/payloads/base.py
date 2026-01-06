class Payload:
    def __init__(self, value: str, context: str):
        self.value = value
        self.context = context  # html, attr, js, url

    def __str__(self):
        return self.value

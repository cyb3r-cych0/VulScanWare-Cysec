from core.payload_plugins.base import PayloadPlugin


class URLPayloads(PayloadPlugin):
    name = "url_payloads"
    context = "url"

    def get_payloads(self):
        return [
            "javascript:alert(1)"
        ]
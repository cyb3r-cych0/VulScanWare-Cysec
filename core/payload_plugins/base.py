class PayloadPlugin:
    name = "base"
    context = "html"   # html | attribute | javascript | url

    def get_payloads(self):
        return []
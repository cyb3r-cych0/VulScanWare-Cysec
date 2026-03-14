import re


class ReflectionContextAnalyzer:

    def analyze(self, response_text, payload):

        idx = response_text.find(payload)

        if idx == -1:
            return None

        window = response_text[max(idx-120,0):idx+120]

        # HTML attribute
        if re.search(r'\w+="[^"]*' + re.escape(payload), window):
            return "attribute"

        # script block
        if "<script" in window.lower():
            return "javascript"

        # href or src
        if re.search(r'(href|src)=', window, re.I):
            return "url"

        return "html"
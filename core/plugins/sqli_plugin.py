from core.plugins.base import VulnPlugin
import requests


class SQLiPlugin(VulnPlugin):

    name = "sqli"

    def scan(self, injection):

        if injection["method"] != "GET":
            return None

        url = injection["url"]

        try:
            r = requests.get(url, timeout=5)
        except:
            return None

        if "SQL syntax" in r.text:
            return {
                "type": "SQL Injection",
                "url": url
            }
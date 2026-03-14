from urllib.parse import urlparse, urlencode, urlunparse

COMMON_PARAMS = [
    "id",
    "page",
    "file",
    "url",
    "redirect",
    "search",
    "q",
    "query",
    "lang",
    "view",
    "next"
]


class ParameterDiscoveryEngine:

    def discover(self, url):

        parsed = urlparse(url)

        discovered = []

        for param in COMMON_PARAMS:

            new_query = urlencode({param: "VSW_TEST"})

            new_url = urlunparse(
                parsed._replace(query=new_query)
            )

            discovered.append({
                "url": new_url,
                "parameter": param,
                "method": "GET"
            })

        return discovered
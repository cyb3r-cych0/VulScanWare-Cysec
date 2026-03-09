import requests


class FormReplayEngine:

    def __init__(self, timeout=5):
        self.timeout = timeout
        self.replayed = set()

    def replay(self, injection):

        url = injection["url"]
        method = injection["method"]
        data = injection.get("data", {})

        key = (url, str(data))

        if key in self.replayed:
            return

        try:

            if method == "POST":

                requests.post(
                    url,
                    data=data,
                    timeout=self.timeout
                )

            else:

                requests.get(
                    url,
                    params=data,
                    timeout=self.timeout
                )

            self.replayed.add(key)

        except requests.RequestException:
            pass

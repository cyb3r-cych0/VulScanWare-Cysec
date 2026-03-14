class VulnPlugin:

    name = "base"

    def scan(self, injection):
        """
        injection = {
            url,
            method,
            payload,
            parameter,
            data
        }

        return Vulnerability or None
        """
        raise NotImplementedError
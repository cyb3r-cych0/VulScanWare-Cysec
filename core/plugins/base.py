class PluginBase:
    name = "base"
    plugin_type = "detector"   # detector | discovery | analytics
    version = "1.0"

    def run(self, injection):
        """
        Detector plugins override this.
        """
        return []

    def discover(self, url):
        """
        Discovery plugins override this.
        """
        return []


class DetectorPlugin:
    name = "detector"

    def run(self, injection):
        raise NotImplementedError
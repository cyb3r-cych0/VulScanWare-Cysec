from core.plugins.base import PluginBase
from core.discovery.param_discovery import ParameterDiscoveryEngine


class ParameterDiscoveryPlugin(PluginBase):

    name = "parameter_discovery"
    plugin_type = "discovery"

    def __init__(self):
        self.engine = ParameterDiscoveryEngine()

    def discover(self, url):

        return self.engine.discover(url)
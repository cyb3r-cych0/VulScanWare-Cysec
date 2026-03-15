from core.plugins.base import PluginBase
from core.dom.playwright_dom import DomXSSDetector


class DOMXSSPlugin(PluginBase):
    plugin_type = "detector"
    scope = "page"

    def __init__(self):
        self.detector = DomXSSDetector()

    def run(self, injection):
        pass
        """ Pass To Reduce Browser Overhead Otherwise Uncomment Code Below"""
        # result = self.detector.scan_page(injection)
        #
        # if result:
        #     return [result]
        # return []
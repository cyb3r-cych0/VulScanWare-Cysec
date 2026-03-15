from core.plugins.base import PluginBase
from core.detector.reflected import ReflectedXSSDetector


class ReflectedXSSPlugin(PluginBase):
    plugin_type = "detector"
    scope = "injection"

    def __init__(self):
        self.detector = ReflectedXSSDetector()

    def run(self, injection):
        result = self.detector.detect(injection)
        if result:
            return [result]
        return []
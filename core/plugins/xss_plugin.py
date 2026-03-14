from core.plugins.base import VulnPlugin
from core.detector.reflected import ReflectedXSSDetector


class XSSPlugin(VulnPlugin):

    name = "xss"

    def __init__(self):
        self.detector = ReflectedXSSDetector()

    def scan(self, injection):
        return self.detector.detect(injection)
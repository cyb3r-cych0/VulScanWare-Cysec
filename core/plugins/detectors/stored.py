from core.plugins.base import PluginBase
from core.detector.stored import StoredXSSTracker


class StoredXSSPlugin(PluginBase):
    plugin_type = "detector"
    scope = "track"

    def __init__(self):
        self.tracker = StoredXSSTracker()

    def run(self, injection):
        self.tracker.track(injection)
        return []
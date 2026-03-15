class PluginRouter:
    def __init__(self, manager):
        self.manager = manager

    def run_detectors(self, injection):
        return self.manager.run_detectors(injection)

    def run_discovery(self, url):
        return self.manager.run_discovery(url)
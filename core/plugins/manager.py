import pkgutil
import importlib
from core.plugins.base import VulnPlugin


class PluginManager:

    def __init__(self):
        self.plugins = []

    def load_plugins(self):

        package = "core.plugins"

        for _, module_name, _ in pkgutil.iter_modules(["core/plugins"]):

            if module_name in ["base", "manager"]:
                continue

            module = importlib.import_module(f"{package}.{module_name}")

            for obj in module.__dict__.values():

                if isinstance(obj, type) and issubclass(obj, VulnPlugin) and obj != VulnPlugin:
                    self.plugins.append(obj())

    def run_plugins(self, injection):

        results = []

        for plugin in self.plugins:

            try:
                finding = plugin.scan(injection)

                if finding:
                    results.append(finding)

            except Exception:
                pass

        return results
import pkgutil
import importlib
from core.plugins.base import PluginBase


class PluginManager:
    def __init__(self):
        self.plugins = []
        self.detectors = []
        self.discovery = []
        # cached execution lists
        self.injection_detectors = []
        self.page_detectors = []


    def load_plugins(self):
        package = "core.plugins.detectors"
        package_module = importlib.import_module(package)

        for finder, module_name, ispkg in pkgutil.walk_packages(
                package_module.__path__,
                package + "."
        ):
            # skip core files
            if module_name.endswith(("base", "manager")):
                continue
            try:
                module = importlib.import_module(module_name)
                for attr in dir(module):
                    obj = getattr(module, attr)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, PluginBase)
                        and obj is not PluginBase
                    ):
                        plugin = obj()
                        self.plugins.append(plugin)

                        if getattr(plugin, "plugin_type", None) == "detector":
                            self.detectors.append(plugin)
                            scope = getattr(plugin, "scope", "injection")

                            if scope == "injection":
                                self.injection_detectors.append(plugin)
                            elif scope == "page":
                                self.page_detectors.append(plugin)

                        elif getattr(plugin, "plugin_type", None) == "discovery":
                            self.discovery.append(plugin)
                print("Loaded detectors:", [p.__class__.__name__ for p in self.detectors])
            except Exception as e:
                print(f"[Plugin ERROR] {module_name}: {e}")


    def run_discovery(self, url):
        injections = []
        for plugin in self.discovery:
            try:
                results = plugin.discover(url)
                if results:
                    injections.extend(results)
            except Exception as e:
                print(f"[Discovery Plugin ERROR] {plugin}: {e}")
        return injections


    def run_detectors(self, injection):
        findings = []
        for plugin in self.injection_detectors:
            try:
                result = plugin.run(injection)
                if result:
                    findings.extend(result)
            except Exception as e:
                print(f"[Detector Plugin ERROR] {plugin}: {e}")
        return findings
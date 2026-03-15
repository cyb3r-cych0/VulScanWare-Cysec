import pkgutil
import importlib
from core.payload_plugins.base import PayloadPlugin


class PayloadManager:
    def __init__(self):
        self.payloads = {}
        # structure:
        # {
        #   "html": [...],
        #   "attribute": [...],
        #   "javascript": [...],
        #   "url": [...]
        # }

    def load(self):
        package = "core.payload_plugins"
        package_module = importlib.import_module(package)

        for _, module_name, _ in pkgutil.iter_modules(package_module.__path__):
            if module_name in ["base", "manager"]:
                continue
            try:
                module = importlib.import_module(
                    f"{package}.{module_name}"
                )
                for attr in dir(module):
                    obj = getattr(
                        module, attr
                    )
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, PayloadPlugin)
                        and obj is not PayloadPlugin
                    ):
                        plugin = obj()
                        ctx = plugin.context

                        if ctx not in self.payloads:
                            self.payloads[ctx] = []

                        self.payloads[ctx].extend(
                            plugin.get_payloads()
                        )
            except Exception as e:
                print(f"[PayloadPlugin ERROR] {module_name}: {e}")

    def get(self, context):
        return self.payloads.get(context, [])
import json
import hashlib
from pathlib import Path

CACHE_FILE = Path("ai_cache.json")


class AICache:

    def __init__(self):
        if CACHE_FILE.exists():
            self.cache = json.loads(CACHE_FILE.read_text())
        else:
            self.cache = {}

    def _save(self):
        CACHE_FILE.write_text(json.dumps(self.cache, indent=2))

    @staticmethod
    def fingerprint(vuln):
        key_string = f"{vuln.url}|{vuln.parameter}|{vuln.vuln_type}|{vuln.payload}"
        return hashlib.sha256(key_string.encode()).hexdigest()

    def get(self, vuln):
        key = self.fingerprint(vuln)
        return self.cache.get(key)

    def set(self, vuln, response):
        key = self.fingerprint(vuln)
        self.cache[key] = response
        self._save()
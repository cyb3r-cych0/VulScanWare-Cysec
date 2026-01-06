import hashlib

class AICache:
    def __init__(self):
        self._cache = {}

    def key(self, context: dict) -> str:
        return hashlib.sha256(str(context).encode()).hexdigest()

    def get(self, context: dict):
        return self._cache.get(self.key(context))

    def set(self, context: dict, value: str):
        self._cache[self.key(context)] = value

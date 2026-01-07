import hashlib

class AICache:
    def __init__(self):
        self._cache = {}

    def get(self, prompt: str):
        return self._cache.get(hashlib.sha256(prompt.encode()).hexdigest())

    def set(self, prompt: str, value: str):
        self._cache[hashlib.sha256(prompt.encode()).hexdigest()] = value

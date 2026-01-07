from core.ai.cache import AICache

def test_ai_cache_with_prompt_string():
    cache = AICache()

    prompt = "Reflected XSS on parameter q"
    value = "Encode output and apply CSP."

    # cache miss
    assert cache.get(prompt) is None

    # cache set
    cache.set(prompt, value)

    # cache hit
    assert cache.get(prompt) == value

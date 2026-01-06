from core.ai.cache import AICache

def test_ai_cache():
    c = AICache()
    ctx = {"vuln": "xss"}
    c.set(ctx, "fix")
    assert c.get(ctx) == "fix"

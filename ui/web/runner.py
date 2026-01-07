"""Background runner (Web only)"""
from core.engine import ScanEngine
from core.ai.prompt import build_prompt
from core.ai.offline import OfflineAIAdvisor
from core.ai.llm_loader import load_llm
from core.ai.cache import AICache
import time

def run_scan(state, target, url_limit, ai_limit):
    start = time.time()
    engine = ScanEngine(url_limit=url_limit)

    def on_discover(url):
        if state.stop:
            state.phase = "stopped"
            return
        state.discovered_urls.append(url)

    state.phase = "crawling"
    urls = engine.crawler.crawl(target, on_discover=on_discover)
    if state.stop:
        state.phase = "stopped"
        return

    state.phase = "scanning"
    for url in urls:
        if state.stop:
            state.phase = "stopped"
            return
        for inj in engine.injector.inject(url):
            if state.stop:
                state.phase = "stopped"
                return
            finding = engine.detector.detect(inj)
            if finding:
                state.vulnerabilities.append(finding)
                finding.severity = "high" if "script" in finding.payload.lower() else "medium"

    if ai_limit and not state.stop:
        state.phase = "ai"
        llm = load_llm("models/mistral-7b-instruct-v0.1.Q4_K_M.gguf")
        ai = OfflineAIAdvisor(llm)
        cache = AICache()

        for i, v in enumerate(state.vulnerabilities):
            if state.stop:
                state.phase = "stopped"
                return
            if i >= ai_limit:
                break
            prompt = build_prompt(v)
            v.ai_fix = cache.get(prompt) or ai.generate_fix(prompt)
            cache.set(prompt, v.ai_fix)

    state.phase = "done"
    state.ai_done = True
    state.elapsed = round(time.time() - start, 2)



"""Background runner (Web only)"""
from core.engine import ScanEngine
import time

def run_scan(state, target, url_limit, ai_limit):
    start = time.time()
    engine = ScanEngine(url_limit=url_limit)

    state.stop = False
    state.paused = False
    state.stopped = False
    state.ai_done = False

    # ---------------- CRAWLING ----------------
    state.phase = "crawling"

    def on_discover(url):
        if state.stop:
            return
        state.discovered_urls.append(url)

    urls = engine.crawler.crawl(target, on_discover=on_discover)

    if state.stop:
        state.phase = "idle"
        return

    # ---------------- SCANNING ----------------
    state.phase = "scanning"

    for url in urls:

        # HARD STOP
        if state.stop:
            state.phase = "idle"
            return

        # PAUSE LOOP
        while state.paused:
            state.phase = "paused"
            time.sleep(0.2)
            if state.stop:
                state.phase = "idle"
                return

        state.phase = "scanning"

        for inj in engine.injector.inject(url):

            if state.stop:
                state.phase = "idle"
                return

            finding = engine.detector.detect(inj)

            if finding:
                finding.severity = (
                    "high" if "script" in finding.payload.lower()
                    else "medium"
                )
                state.vulnerabilities.append(finding)

    # ---------------- COMPLETE ----------------
    if not state.stop:
        state.phase = "done"
        state.ai_done = True
        state.elapsed = round(time.time() - start, 2)

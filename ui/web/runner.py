"""Background runner (Web only)"""
from core.engine import ScanEngine
import time

def run_scan(state, target, url_limit, depth_limit):
    start = time.time()
    engine = ScanEngine(url_limit=url_limit, depth_limit=depth_limit, dom=True)

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

            # TRACK PAYLOAD FOR STORED XSS
            engine.stored_tracker.track(inj)

            finding = engine.detector.detect(inj)

            if finding:
                finding.severity = (
                    "high" if "script" in finding.payload.lower()
                    else "medium"
                )
                state.vulnerabilities.append(finding)

    # ---------------- STORED ANALYSIS ----------------

    state.phase = "stored-analysis"

    # perform second crawl to detect stored payload rendering
    stored_urls = engine.crawler.crawl(target)

    # combine previously crawled + new pages
    all_urls = list(set(urls + stored_urls))

    stored_findings = engine.stored_tracker.check_pages(all_urls)

    for v in stored_findings:
        state.vulnerabilities.append(v)

    # ---------------- COMPLETE ----------------

    if not state.stop:
        state.phase = "done"
        state.ai_done = True
        state.elapsed = round(time.time() - start, 2)

"""Background runner (Web only)"""
from core.engine import ScanEngine
import time
from urllib.parse import urlparse


def run_scan(state, target, url_limit, depth_limit):
    start = time.time()
    engine = ScanEngine(url_limit=url_limit, depth_limit=depth_limit, dom=True)

    state.stop = False
    state.paused = False
    state.stopped = False
    state.ai_done = False

    seen_vulns = set()

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

                # keep severity from detector if already defined
                if not getattr(finding, "severity", None):

                    payload = (finding.payload or "").lower()

                    if "<script" in payload:
                        finding.severity = "high"

                    elif "svg" in payload:
                        finding.severity = "medium"

                    elif "javascript:" in payload:
                        finding.severity = "medium"

                    else:
                        finding.severity = "low"

                endpoint = urlparse(finding.url).path
                param = (finding.parameter or "").lower()

                fingerprint = (
                    endpoint,
                    param,
                    finding.vuln_type
                )

                if fingerprint not in seen_vulns:
                    seen_vulns.add(fingerprint)
                    state.vulnerabilities.append(finding)

    # ---------------- STORED ANALYSIS ----------------

    state.phase = "stored-analysis"

    # perform second crawl to detect stored payload rendering
    stored_urls = engine.crawler.crawl(target)

    # combine previously crawled + new pages
    all_urls = list(set(urls + stored_urls))

    stored_findings = engine.stored_tracker.check_pages(all_urls)

    for v in stored_findings:

        v.severity = "critical"

        endpoint = urlparse(v.url).path
        param = (v.parameter or "").lower()

        fingerprint = (
            endpoint,
            param,
            v.vuln_type
        )

        if fingerprint not in seen_vulns:
            seen_vulns.add(fingerprint)
            state.vulnerabilities.append(v)

    # ---------------- DOM ANALYSIS ----------------
    state.phase = "dom-analysis"

    if engine.dom:

        from core.dom.playwright_dom import DomXSSDetector

        dom_detector = DomXSSDetector()

        for url in all_urls:

            if state.stop:
                state.phase = "idle"
                return

            result = dom_detector.scan_page(url)

            if result:
                state.vulnerabilities.append(result)

    # ---------------- COMPLETE ----------------

    if not state.stop:
        state.phase = "done"
        state.ai_done = True
        state.elapsed = round(time.time() - start, 2)

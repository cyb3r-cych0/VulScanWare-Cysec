from core.crawler.basic import BasicCrawler
from core.injector.basic import BasicInjector
from core.detector.reflected import ReflectedXSSDetector
from core.models import ScanResult
from core.ai.prompt import build_prompt
from core.ai.cache import AICache
from core.detector.stored import StoredXSSTracker
from core.replay.form_replay import FormReplayEngine


class ScanEngine:
    def __init__(
            self,
            crawler=None,
            injector=None,
            detector=None,
            ai=None,
            dom=False,
            url_limit: int = 25,
            depth_limit: int = 2,
    ):
        self.crawler = crawler or BasicCrawler(max_pages=url_limit, max_depth=depth_limit)
        self.injector = injector or BasicInjector()
        self.detector = detector or ReflectedXSSDetector()
        self.stored_tracker = StoredXSSTracker()
        self.dom = dom
        self.ai = ai
        self.replay_engine = FormReplayEngine()
        self.ai_cache = AICache() if ai else None

    def run(self, target: str):
        urls = self.crawler.crawl(target)
        vulns = []

        dom_detector = None
        if self.dom:
            from core.dom.playwright_dom import DomXSSDetector
            dom_detector = DomXSSDetector()

        for url in urls:

            # ---------- DOM XSS scan (run once per URL) ----------
            if self.dom:
                dom_result = dom_detector.scan_page(url)
                if dom_result:
                    vulns.append(dom_result)

            # ---------- Injection testing ----------
            for inj in self.injector.inject(url):

                # track payload for stored detection
                self.stored_tracker.track(inj)

                # replay form submission
                self.replay_engine.replay(inj)

                finding = self.detector.detect(inj)

                if finding and self.ai:
                    ctx = build_prompt(finding)
                    cached = self.ai_cache.get(ctx)
                    if cached:
                        finding.ai_fix = cached
                    else:
                        fix = self.ai.generate_fix(ctx)
                        self.ai_cache.set(ctx, fix)
                        finding.ai_fix = fix

                if finding:
                    vulns.append(finding)

        # ---------- Stored XSS detection ----------
        # perform a second crawl to discover pages where payloads may appear
        stored_urls = self.crawler.crawl(target)

        # combine previously crawled pages + second pass
        all_urls = list(set(urls + stored_urls))

        stored_findings = self.stored_tracker.check_pages(all_urls)
        vulns.extend(stored_findings)

        return ScanResult(target, vulns, len(urls))

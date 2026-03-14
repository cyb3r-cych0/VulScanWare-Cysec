from core.crawler.basic import BasicCrawler
from core.injector.basic import BasicInjector
from core.detector.reflected import ReflectedXSSDetector
from core.models import ScanResult
from core.ai.prompt import build_prompt
from core.ai.cache import AICache
from core.detector.stored import StoredXSSTracker
from core.replay.form_replay import FormReplayEngine
from core.plugins.manager import PluginManager
from core.payloads.adaptive import AdaptiveEngine
from urllib.parse import urlparse
from core.discovery.param_discovery import ParameterDiscoveryEngine


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
        self.plugin_manager = PluginManager()
        self.plugin_manager.load_plugins()
        self.adaptive = AdaptiveEngine()
        self.param_discovery = ParameterDiscoveryEngine()

    def run(self, target: str):
        urls = self.crawler.crawl(target)
        vulns = []
        seen_vulns = set()

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

            # existing parameters
            injections = self.injector.inject(url)

            # parameter discovery (generate new URLs)
            discovered = self.param_discovery.discover(url)

            for d in discovered:
                injections.extend(self.injector.inject(d["url"]))

            for inj in injections:

                # track payload for stored detection
                self.stored_tracker.track(inj)

                # replay form submission
                self.replay_engine.replay(inj)

                # -------- Adaptive payload analysis --------
                if "response" in inj:

                    result = self.adaptive.analyze(
                        inj["response"].text,
                        inj["payload"]
                    )

                    if result != "reflected":
                        new_payload = self.adaptive.mutate(
                            inj["payload"],
                            result
                        )

                        inj["payload"] = new_payload

                findings = self.plugin_manager.run_plugins(inj)

                for f in findings:

                    endpoint = urlparse(f.url).path
                    param = (f.parameter or "").lower()

                    key = (endpoint, param, f.vuln_type)

                    if key in seen_vulns:
                        continue

                    seen_vulns.add(key)
                    vulns.append(f)

                    if self.ai:
                        ctx = build_prompt(f)
                        cached = self.ai_cache.get(ctx)

                        if cached:
                            f.ai_fix = cached
                        else:
                            fix = self.ai.generate_fix(ctx)
                            self.ai_cache.set(ctx, fix)
                            f.ai_fix = fix

        # ---------- Stored XSS detection ----------
        # perform a second crawl to discover pages where payloads may appear
        stored_urls = self.crawler.crawl(target)

        # combine previously crawled pages + second pass
        all_urls = list(set(urls + stored_urls))

        stored_findings = self.stored_tracker.check_pages(all_urls)

        for f in stored_findings:

            endpoint = urlparse(f.url).path
            param = (f.parameter or "").lower()

            key = (endpoint, param, f.vuln_type)

            if key in seen_vulns:
                continue

            seen_vulns.add(key)
            vulns.append(f)

        return ScanResult(target, vulns, len(urls))

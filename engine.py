from core.crawler.basic import BasicCrawler
from core.injector.basic import BasicInjector
from core.detector.reflected import ReflectedXSSDetector
from core.models import ScanResult
from core.ai.prompt import build_prompt
from core.ai.cache import AICache


class ScanEngine:
    def __init__(
            self,
            crawler=None,
            injector=None,
            detector=None,
            ai=None,
            dom=False,
    ):
        self.crawler = crawler or BasicCrawler()
        self.injector = injector or BasicInjector()
        self.detector = detector or ReflectedXSSDetector()
        self.dom = dom
        self.ai = ai
        self.ai_cache = AICache() if ai else None

    def run(self, target: str):
        urls = self.crawler.crawl(target)
        vulns = []

        dom_detector = None
        if self.dom:
            from core.dom.playwright_dom import DomXSSDetector
            dom_detector = DomXSSDetector()

        for url in urls:
            for inj in self.injector.inject(url):
                finding = self.detector.detect(inj)
                if not finding and dom_detector:
                    finding = dom_detector.detect(inj)

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

        return ScanResult(target, vulns, len(urls))

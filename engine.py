from core.crawler.basic import BasicCrawler
from core.injector.basic import BasicInjector
from core.detector.reflected import ReflectedXSSDetector
from core.models import ScanResult
from core.ai.prompt import build_prompt


class ScanEngine:
    def __init__(self, crawler=None, injector=None, detector=None, ai=None):
        self.crawler = crawler or BasicCrawler()
        self.injector = injector or BasicInjector()
        self.detector = detector or ReflectedXSSDetector()
        self.ai = ai


    def run(self, target: str) -> ScanResult:
        urls = self.crawler.crawl(target)
        vulns = []

        for url in urls:
            for inj in self.injector.inject(url):
                finding = self.detector.detect(inj)
                if finding and self.ai:
                    ctx = build_prompt(finding)
                    finding.ai_fix = self.ai.generate_fix(ctx)
                if finding:
                    vulns.append(finding)

        return ScanResult(target, vulns, len(urls))

        # return ScanResult(
        #     target=target,
        #     vulnerabilities=vulns,
        #     scanned_urls=len(urls)
        # )

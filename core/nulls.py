class NullCrawler:
    def crawl(self, target):
        return []

class NullInjector:
    def inject(self, url):
        return []

class NullDetector:
    def detect(self, injection):
        return None

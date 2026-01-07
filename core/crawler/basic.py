from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

class BasicCrawler:
    def __init__(self, timeout=5, max_pages=25):
        self.timeout = timeout
        self.max_pages = max_pages

    def crawl(self, target: str, on_discover=None):
        visited = set()
        to_visit = [target]
        origin = urlparse(target).netloc

        while to_visit and len(visited) < self.max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue

            try:
                r = requests.get(url, timeout=self.timeout, allow_redirects=True)
                if "text/html" not in r.headers.get("Content-Type", ""):
                    continue
            except requests.RequestException:
                continue

            visited.add(url)

            if on_discover:
                on_discover(url)

            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                parsed = urlparse(link)

                if parsed.netloc == origin and link not in visited:
                    to_visit.append(link)

        return list(visited)

from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup


class BasicCrawler:

    def __init__(self, timeout=5, max_pages=25, max_depth=2):
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_depth = max_depth


    def crawl(self, target: str, on_discover=None):

        visited = set()

        # queue now stores (url, depth)
        to_visit = [(target, 0)]

        origin = urlparse(target).netloc


        while to_visit and len(visited) < self.max_pages:

            url, depth = to_visit.pop(0)

            if url in visited:
                continue

            if depth > self.max_depth:
                continue

            try:

                r = requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "VulScanWare"}
                )

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

                if parsed.netloc != origin:
                    continue


                if link not in visited:

                    if len(visited) + len(to_visit) < self.max_pages:

                        # add next depth level
                        to_visit.append((link, depth + 1))


        return list(visited)
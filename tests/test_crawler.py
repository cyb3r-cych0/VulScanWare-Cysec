from core.crawler.basic import BasicCrawler

class FakeResponse:
    headers = {"Content-Type": "text/html"}
    text = '<a href="/page1">p1</a><a href="/page2">p2</a>'

def fake_get(url, timeout, allow_redirects):
    return FakeResponse()

def test_crawler_internal_links(monkeypatch):
    import requests
    monkeypatch.setattr(requests, "get", fake_get)

    crawler = BasicCrawler(max_pages=5)
    urls = crawler.crawl("http://example.com")

    assert "http://example.com" in urls
    assert "http://example.com/page1" in urls
    assert "http://example.com/page2" in urls

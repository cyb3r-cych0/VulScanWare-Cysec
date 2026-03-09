from playwright.sync_api import sync_playwright
from core.models import Vulnerability

JS_HOOKS = r"""
(() => {
  window.__xss_hits = [];
  const hit = (t) => window.__xss_hits.push(t);

  const _alert = window.alert;
  window.alert = function(){ hit("alert"); return _alert.apply(this, arguments); };

  const _confirm = window.confirm;
  window.confirm = function(){ hit("confirm"); return _confirm.apply(this, arguments); };

  const _prompt = window.prompt;
  window.prompt = function(){ hit("prompt"); return _prompt.apply(this, arguments); };

  const _eval = window.eval;
  window.eval = function(){ hit("eval"); return _eval.apply(this, arguments); };

  const _write = document.write;
  document.write = function(){ hit("document.write"); return _write.apply(this, arguments); };

  const desc = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
  Object.defineProperty(Element.prototype, "innerHTML", {
    set(v){ hit("innerHTML"); return desc.set.call(this, v); },
    get(){ return desc.get.call(this); }
  });
})();
"""

class DomXSSDetector:
    def __init__(self, timeout_ms=8000):
        self.timeout_ms = timeout_ms

    def detect(self, injection: dict):
        url = injection["url"]
        payload = injection["payload"]

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            # install hooks before any script runs
            page.add_init_script(JS_HOOKS)

            try:
                page.goto(url, timeout=self.timeout_ms)
                page.wait_for_timeout(500)  # allow JS execution
                hits = page.evaluate("window.__xss_hits || []")
            except Exception:
                browser.close()
                return None

            browser.close()

        if hits:
            return Vulnerability(
                vuln_type="DOM XSS",
                url=url,
                parameter=injection.get("parameter", ""),
                method=injection.get("method", "GET"),
                payload=payload,
                evidence=f"JS sink triggered: {', '.join(set(hits))}",
                severity="critical"
            )
        return None

    def scan_page(self, url):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            page.add_init_script(JS_HOOKS)

            try:
                page.goto(url, timeout=self.timeout_ms)
                page.wait_for_timeout(500)
                hits = page.evaluate("window.__xss_hits || []")
            except Exception:
                browser.close()
                return None

            browser.close()

        if hits:
            return Vulnerability(
                vuln_type="DOM XSS",
                url=url,
                parameter="",
                method="GET",
                payload="DOM-SCAN",
                evidence=f"JS sink triggered: {', '.join(set(hits))}",
                severity="high"
            )

        return None

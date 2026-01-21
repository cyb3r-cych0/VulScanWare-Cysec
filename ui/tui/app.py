from rich.live import Live
from rich.console import Console
import time
import threading
import msvcrt


from ui.tui.state import UIState
from ui.tui.render import build_layout, build_summary
from core.engine import ScanEngine

console = Console()


def listen_for_keys(state, stop_event, live):
    while not stop_event.is_set():
        if msvcrt.kbhit():
            key = msvcrt.getch().decode(errors="ignore").lower()
            if key == "q":
                stop_event.set()
            elif key == "p":
                state.phase = "paused"
                live.update(build_layout(state))
            elif key == "r":
                state.phase = "scanning"
                live.update(build_layout(state))
        time.sleep(0.1)

def run_tui(target, url_limit, ai_limit):
    start_time = time.time()
    state = UIState(phase="crawling")
    engine = ScanEngine(url_limit=url_limit)
    urls_scanned = 0
    ai_count = 0

    with Live(console=console, refresh_per_second=1) as live:
        stop_event = threading.Event()

        listener = threading.Thread(
            target=listen_for_keys,
            args=(state, stop_event, live),
            daemon=True,
        )
        listener.start()

        def on_discover(url):
            state.discovered_urls.append(url)
            live.update(build_layout(state))

        urls = engine.crawler.crawl(target, on_discover=on_discover)

        state.phase = "scanning"
        live.update(build_layout(state))

        for url in urls:
            while state.phase == "paused" and not stop_event.is_set():
                time.sleep(0.2)
            if stop_event.is_set():
                break

            urls_scanned += 1
            for inj in engine.injector.inject(url):
                if stop_event.is_set():
                    break
                finding = engine.detector.detect(inj)
                if finding:
                    state.vulnerabilities.append(finding)
                    live.update(build_layout(state))

        if ai_limit and state.vulnerabilities:
            from core.ai.llm_loader import load_llm
            from core.ai.offline import OfflineAIAdvisor
            from core.ai.prompt import build_prompt
            from core.ai.cache import AICache

            state.phase = "ai"
            live.update(build_layout(state))

            llm = load_llm("models/mistral-7b-instruct-v0.1.Q4_K_M.gguf")
            ai = OfflineAIAdvisor(llm)
            cache = AICache()

            for i, v in enumerate(state.vulnerabilities):
                if i >= ai_limit:
                    break

                prompt = build_prompt(v)
                cached = cache.get(prompt)
                v.ai_fix = cached or ai.generate_fix(prompt)
                ai_count += 1
                if not cached:
                    cache.set(prompt, v.ai_fix)

                live.update(build_layout(state))

            state.ai_done = True

        state.phase = "done"
        elapsed = round(time.time() - start_time, 2)

        state.phase = "done"

        summary = build_summary(
            state,
            urls_crawled=len(urls),
            urls_scanned=urls_scanned,
            ai_count=ai_count,
            elapsed=elapsed,
        )

        live.update(build_layout(state))
        live.console.print(summary)

        # persist until user quits
        while not stop_event.is_set():
            time.sleep(0.2)


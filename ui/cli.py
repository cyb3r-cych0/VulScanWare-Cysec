import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from core.engine import ScanEngine
from ui.tui.app import run_tui


app = typer.Typer(add_completion=False)
console = Console()

@app.command()
def tui(
    target: str,
    url_limit: int = 25,
    ai_limit: int = 3,
):
    run_tui(target, url_limit, ai_limit)

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL"),
    offline: bool = typer.Option(False, help="Use offline AI remediation"),
    url_limit: int = typer.Option(
        25,
        help="Maximum number of URLs to crawl",
    ),
    ai_limit: int = typer.Option(
        3,
        help="Maximum number of vulnerabilities to analyze with AI (0 disables AI)",
    ),
    report: bool = typer.Option(False, help="Generate HTML report"),
):

    console.print(
        Panel.fit(
            "[bold cyan]VulScanWare[/bold cyan]\n"
            "[dim]AI-enhanced XSS vulnerability scanner[/dim]",
            border_style="cyan"
        )
    )

    console.print(f"[bold]Target:[/bold] [yellow]{target}[/yellow]\n")

    engine = ScanEngine(url_limit=url_limit)

    # ---- CRAWLING ----
    console.print("[bold blue][*][/bold blue] Crawling target…")

    discovered_urls = []

    def on_discover(url):
        discovered_urls.append(url)
        console.print(f"    [dim]├─ Discovered:[/dim] {url}")

    urls = engine.crawler.crawl(
        target,
        on_discover=on_discover
    )

    console.print(
        f"[bold green][✓][/bold green] Crawling complete "
        f"([bold]{len(urls)}[/bold] URLs)\n"
    )

    # ---- INJECTION + SCAN ----
    console.print("[bold blue][*][/bold blue] Scanning for reflected XSS…")

    vulnerabilities = []
    total_injections = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task("Scanning…", total=len(urls))

        for url in urls:
            injections = engine.injector.inject(url)
            total_injections += len(injections)

            for inj in injections:
                finding = engine.detector.detect(inj)
                if finding:
                    vulnerabilities.append(finding)
                    console.print(
                        f"    [red]✖ Vulnerable:[/red] {finding.url} "
                        f"[dim]({finding.parameter})[/dim]"
                    )

            progress.advance(task)

    console.print(
        f"[bold green][✓][/bold green] Scan complete "
        f"([bold]{len(vulnerabilities)}[/bold] vulnerabilities)\n"
    )

    # ---- AI REMEDIATION ----
    if offline and vulnerabilities and ai_limit != 0:
        console.print(
            f"[bold blue][*][/bold blue] Generating AI remediation "
            f"(showing first {min(ai_limit, len(vulnerabilities))} findings)…\n"
        )

        from core.ai.llm_loader import load_llm
        from core.ai.offline import OfflineAIAdvisor
        from core.ai.prompt import build_prompt
        from core.ai.cache import AICache

        llm = load_llm("models/mistral-7b-instruct-v0.1.Q4_K_M.gguf")
        ai = OfflineAIAdvisor(llm)
        cache = AICache()

        for i, v in enumerate(vulnerabilities):
            if i >= ai_limit:
                break

            prompt = build_prompt(v)
            cached = cache.get(prompt)

            console.print(
                f"    [cyan]•[/cyan] {v.vuln_type}\n"
                f"      URL: {v.url}\n"
                f"      Parameter: {v.parameter}"
            )

            if cached:
                v.ai_fix = cached
            else:
                v.ai_fix = ai.generate_fix(prompt)
                cache.set(prompt, v.ai_fix)

            console.print(
                f"      [dim]└─ Recommendation:[/dim]\n"
                f"         {v.ai_fix}\n"
            )

        remaining = len(vulnerabilities) - ai_limit
        if remaining > 0:
            console.print(
                f"[dim]… {remaining} additional findings skipped "
                f"(increase --ai-limit to analyze more)[/dim]\n"
            )

        console.print("[bold green][✓][/bold green] AI remediation complete\n")

    # ---- SUMMARY ----
    table = Table(title="Findings Summary", show_lines=True)
    table.add_column("Type", style="red")
    table.add_column("Parameter")
    table.add_column("Payload", overflow="fold")

    for v in vulnerabilities:
        table.add_row(v.vuln_type, v.parameter, v.payload)

    console.print(table)

    console.print(
        Panel.fit(
            f"[bold green]Scan finished[/bold green]\n"
            f"URLs scanned: [bold]{len(urls)}[/bold]\n"
            f"Injection points: [bold]{total_injections}[/bold]\n"
            f"Vulnerabilities: [bold red]{len(vulnerabilities)}[/bold red]",
            border_style="green"
        )
    )

def main():
    app()

if __name__ == "__main__":
    main()

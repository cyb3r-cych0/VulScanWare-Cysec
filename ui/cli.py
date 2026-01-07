import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from core.engine import ScanEngine

app = typer.Typer(add_completion=False)
console = Console()

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL"),
    offline: bool = typer.Option(False, help="Use offline AI remediation"),
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

    engine = ScanEngine()

    # ---- CRAWLING ----
    console.print("[bold blue][*][/bold blue] Crawling target…")

    urls = engine.crawler.crawl(target)

    for u in urls:
        console.print(f"    [dim]├─ Discovered:[/dim] {u}")

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
    if offline and vulnerabilities:
        console.print("[bold blue][*][/bold blue] Generating AI remediation…")

        from core.ai.llm_loader import load_llm
        from core.ai.offline import OfflineAIAdvisor
        from core.ai.prompt import build_prompt

        llm = load_llm("models/mistral-7b-instruct.Q4_K_M.gguf")
        ai = OfflineAIAdvisor(llm)

        for v in vulnerabilities:
            console.print(
                f"    [cyan]•[/cyan] {v.vuln_type} → AI advice"
            )
            v.ai_fix = ai.generate_fix(build_prompt(v))

        console.print("[bold green][✓][/bold green] AI analysis complete\n")

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

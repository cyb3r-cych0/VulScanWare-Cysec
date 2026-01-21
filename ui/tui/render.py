from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table


def build_layout(state):
    layout = Layout()

    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )

    layout["body"].split_row(
        Layout(name="crawl"),
        Layout(name="vulns"),
        Layout(name="ai"),
    )

    # Header
    layout["header"].update(
        Panel(f"[bold cyan]VulScanWare[/bold cyan] | Phase: {state.phase}")
    )

    # Crawl table
    crawl = Table(title="Discovered URLs", expand=True)
    crawl.add_column("URL", overflow="fold")
    for u in state.discovered_urls[-15:]:
        crawl.add_row(u)
    layout["body"]["crawl"].update(crawl)

    # Vulnerabilities table
    vulns = Table(title=f"Vulnerabilities ({len(state.vulnerabilities)})", expand=True)
    vulns.add_column("Type", style="red")
    vulns.add_column("URL", overflow="fold")
    vulns.add_column("Param")
    for v in state.vulnerabilities[-15:]:
        vulns.add_row(v.vuln_type, v.url, v.parameter)
    layout["body"]["vulns"].update(vulns)

    # AI Panel
    ai = Table(title="AI Remediation", expand=True)
    ai.add_column("Finding")
    ai.add_column("Advice", overflow="fold")

    for v in state.vulnerabilities:
        if getattr(v, "ai_fix", None):
            ai.add_row(
                f"{v.vuln_type} ({v.parameter})",
                v.ai_fix,
            )

    layout["body"]["ai"].update(ai)

    # Footer
    layout["footer"].update(
        Panel("[dim]Pause (p) | Resume (r) | Quit (q)[/dim]")
    )

    return layout

def build_summary(state, urls_crawled, urls_scanned, ai_count, elapsed):
    table = Table(title="Scan Summary", expand=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")

    table.add_row("URLs Crawled", str(urls_crawled))
    table.add_row("URLs Scanned", str(urls_scanned))
    table.add_row("Vulnerabilities Found", str(len(state.vulnerabilities)))
    table.add_row("AI Remediations", str(ai_count))
    table.add_row("Time Taken (s)", str(elapsed))

    return table


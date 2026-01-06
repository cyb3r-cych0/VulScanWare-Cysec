import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from engine import ScanEngine

app = typer.Typer(add_completion=False)
console = Console()

@app.command()
def scan(target: str = "http://example.com"):
    engine = ScanEngine()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning target...", start=True)
        result = engine.run(target)
        progress.update(task, description="Scan complete")

    table = Table(title="VulScanWare – XSS Findings")
    table.add_column("Type", style="red")
    table.add_column("Method")
    table.add_column("Parameter")
    table.add_column("Payload", overflow="fold")

    for v in result.vulnerabilities:
        table.add_row(
            v.vuln_type,
            v.method,
            v.parameter,
            v.payload
        )

    console.print(table)
    console.print(f"[bold green]Scanned URLs:[/] {result.scanned_urls}")
    console.print(f"[bold red]Findings:[/] {len(result.vulnerabilities)}")

def main():
    app()

if __name__ == "__main__":
    main()

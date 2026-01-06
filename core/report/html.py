from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from core.report.base import ReportGenerator


TEMPLATES_DIR = Path(__file__).parent / "templates"

env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))

class HTMLReport(ReportGenerator):
    def generate(self, scan_result, out_file="report.html"):
        template = env.get_template("report.html")
        html = template.render(result=scan_result)

        with open(out_file, "w", encoding="utf-8") as f:
            f.write(html)

        return out_file

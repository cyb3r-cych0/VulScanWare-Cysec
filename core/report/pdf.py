from weasyprint import HTML

class PDFReport:
    def generate(self, html_file, out_file="report.pdf"):
        HTML(html_file).write_pdf(out_file)
        return out_file

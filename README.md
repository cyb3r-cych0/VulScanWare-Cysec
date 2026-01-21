# VulScanWare

Lightweight, AI-enhanced XSS vulnerability scanner with CLI/TUI and Web UI.

## Installation
```bash
git clone <repo-url>
cd VulScanWare
python -m venv .venv
.venv\Scripts\activate    # Windows
pip install -r requirements.txt
pip install -e .
```

**(Optional) Run tests:**

```bash
pytest
```

### Run — Terminal (CLI / TUI)

**Interactive terminal scanner:**

```bash
vulscanware tui http://TARGET_URL
```

**Example:**

```bash
vulscanware tui http://192.168.23.130/mutillidae/index.php
```

- Runs crawler, scanner, and AI locally
- No server required
- Offline AI loads automatically when needed

### Run — Web UI

**Start the backend + web interface:**

```bash
uvicorn ui.web.app:app --reload
```

**Open in browser:**

```bash
http://127.0.0.1:8000
```

**From the Web UI you can:**

- Set crawl & AI limits
- Start / stop scans
- View live progress
- Download HTML / PDF reports

**Notes**

- No separate backend service required
- Offline LLM (Mistral via llama.cpp) is lazy-loaded
- CLI/TUI and Web UI work independently
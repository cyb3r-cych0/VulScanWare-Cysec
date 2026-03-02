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

**Screenshots**

![Screenshot 2026-02-03 155310.png](screenshots/Screenshot%202026-02-03%20155310.png)
![Screenshot 2026-02-04 052047.png](screenshots/Screenshot%202026-02-04%20052047.png)
![Screenshot 2026-02-04 052056.png](screenshots/Screenshot%202026-02-04%20052056.png)
![Screenshot 2026-02-04 052141.png](screenshots/Screenshot%202026-02-04%20052141.png)
![Screenshot 2026-02-04 052153.png](screenshots/Screenshot%202026-02-04%20052153.png)
![Screenshot 2026-02-04 052204.png](screenshots/Screenshot%202026-02-04%20052204.png)
![Screenshot 2026-02-04 052226.png](screenshots/Screenshot%202026-02-04%20052226.png)
![Screenshot 2026-02-04 052259.png](screenshots/Screenshot%202026-02-04%20052259.png)
![Screenshot 2026-02-04 052313.png](screenshots/Screenshot%202026-02-04%20052313.png)
![Screenshot 2026-02-04 052442.png](screenshots/Screenshot%202026-02-04%20052442.png)
![Screenshot 2026-02-04 052625.png](screenshots/Screenshot%202026-02-04%20052625.png)
![Screenshot 2026-02-04 052700.png](screenshots/Screenshot%202026-02-04%20052700.png)

Advanced AI-Assisted Security Intelligence Platform
import os
from datetime import datetime


DEBUG = os.getenv("VSW_DEBUG", "0") == "1"
LOG_FILE = "vsw_payloads.log"


def log_injection(method, url, param, payload, data=None):

    if not DEBUG:
        return

    ts = datetime.now().strftime("%H:%M:%S")
    entry = f"[{ts}] {method} {url} | {param}={payload}"

    if data:
        entry += f" | DATA={data}"

    print(entry)

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception:
        pass
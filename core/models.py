from dataclasses import dataclass
from typing import List, Optional


@dataclass
class PayloadResult:
    payload: str
    reflected: bool
    evidence: Optional[str] = None


@dataclass
class Vulnerability:
    vuln_type: str
    url: str
    parameter: str
    method: str
    payload: str
    evidence: str
    severity: str = "high"
    context: Optional[str] = None
    ai_fix: Optional[str] = None


@dataclass
class ScanResult:
    target: str
    vulnerabilities: List[Vulnerability]
    scanned_urls: int
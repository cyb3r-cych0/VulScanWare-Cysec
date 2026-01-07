"""Shared UI State"""
from dataclasses import dataclass, field

@dataclass
class UIState:
    phase: str = "idle"
    discovered_urls: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    ai_done: bool = False


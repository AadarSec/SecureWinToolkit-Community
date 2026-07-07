from dataclasses import dataclass
from typing import Optional


@dataclass
class AuditResult:
    name: str
    status: str
    value: str
    recommendation: str
    details: Optional[str] = ""
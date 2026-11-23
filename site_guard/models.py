from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "ℹ️"}


@dataclass
class Finding:
    site: str
    check: str
    severity: str
    title: str
    detail: str = ""
    fix: str = ""
    # Stable identity used to decide whether this finding is new since the last run.
    key: str = field(default="")
    # Set from config when the owner has already handled / scheduled this item.
    ack_note: str = ""
    ack_expired: bool = False

    @property
    def acknowledged(self) -> bool:
        return bool(self.ack_note) and not self.ack_expired

    def __post_init__(self) -> None:
        if not self.key:
            self.key = f"{self.check}:{self.title}"

    def as_dict(self) -> dict:
        return {
            "site": self.site,
            "check": self.check,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "fix": self.fix,
            "key": self.key,
        }

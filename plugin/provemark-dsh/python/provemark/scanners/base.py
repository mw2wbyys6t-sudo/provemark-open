from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..cache import Cache
from ..config import Config
from ..models import Finding
from .deps import DepsResult
from .files import FileInfo


@dataclass
class Context:
    root: Path
    config: Config
    files: list[FileInfo]
    deps: DepsResult
    cache: Cache
    offline: bool = False
    staged: set[str] | None = None
    notes: list[str] = field(default_factory=list)
    network_used: bool = False
    # Set when an online lookup was attempted and failed (proxy, DNS, registry
    # outage). The scan may still be complete for local rules, but any conclusion
    # about dependencies is partial — the score must say so.
    network_failed: bool = False
    unverified_packages: int = 0
    sbom: Path | None = None
    license_resolved: dict[str, str] = field(default_factory=dict)

    def in_scope(self, rel: str) -> bool:
        if self.staged is None:
            return True
        return rel in self.staged

    def scoped_files(self) -> list[FileInfo]:
        if self.staged is None:
            return self.files
        return [f for f in self.files if f.rel in self.staged]

    def note(self, message: str) -> None:
        self.notes.append(message)


def make_finding(rule_id: str, category: str, severity: str, title: str, message: str, **kwargs) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        message=message,
        **kwargs,
    )

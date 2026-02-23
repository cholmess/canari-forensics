from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from canari_forensics.version import __version__


@dataclass(frozen=True)
class WorkspaceStatus:
    version: str
    has_config: bool
    audits_count: int
    latest_audit: str | None


def collect_status(root: str | Path = ".") -> WorkspaceStatus:
    base = Path(root)
    config = base / ".canari.yml"
    audits_root = base / ".canari" / "audits"

    audit_dirs = []
    if audits_root.exists():
        audit_dirs = sorted([p for p in audits_root.iterdir() if p.is_dir()], key=lambda p: p.stat().st_mtime)

    latest = audit_dirs[-1].name if audit_dirs else None

    return WorkspaceStatus(
        version=__version__,
        has_config=config.exists(),
        audits_count=len(audit_dirs),
        latest_audit=latest,
    )

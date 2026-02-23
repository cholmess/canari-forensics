from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def file_sha256(path: str | Path) -> str:
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def create_attestation(evidence_path: str | Path, out_path: str | Path) -> dict[str, Any]:
    evidence = Path(evidence_path)
    digest = file_sha256(evidence)
    payload = {
        "artifact": str(evidence),
        "sha256": digest,
        "type": "canari-evidence-attestation",
    }

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def verify_attestation(attestation_path: str | Path) -> bool:
    data = json.loads(Path(attestation_path).read_text(encoding="utf-8"))
    artifact = data["artifact"]
    expected = data["sha256"]
    actual = file_sha256(artifact)
    return actual == expected

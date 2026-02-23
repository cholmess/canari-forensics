from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


def run_doctor(root: str | Path = ".") -> list[CheckResult]:
    base = Path(root)
    checks: list[CheckResult] = []

    cfg = base / ".canari.yml"
    checks.append(CheckResult("config_file", cfg.exists(), str(cfg)))

    canari_bin = shutil.which("canari")
    checks.append(CheckResult("canari_on_path", canari_bin is not None, canari_bin or "not found"))

    tests_dir = base / "tests"
    checks.append(CheckResult("tests_dir", tests_dir.exists(), str(tests_dir)))

    out_dir = base / ".canari"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        probe = out_dir / ".doctor-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        writable = True
        detail = str(out_dir)
    except Exception as exc:  # pragma: no cover
        writable = False
        detail = str(exc)
    checks.append(CheckResult("workspace_writable", writable, detail))

    return checks


def doctor_payload(root: str | Path = ".") -> dict[str, Any]:
    checks = run_doctor(root)
    return {
        "ok": all(c.ok for c in checks),
        "checks": [asdict(c) for c in checks],
    }

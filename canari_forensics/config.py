from __future__ import annotations

from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    pass


def load_simple_yaml(path: str | Path) -> dict[str, Any]:
    """Load a small subset of YAML (key/value + one-level nested maps)."""
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"Config file not found: {p}")

    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(0, root)]

    for lineno, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        if indent % 2 != 0:
            raise ConfigError(f"Invalid indentation at line {lineno}")

        stripped = line.strip()
        if ":" not in stripped:
            raise ConfigError(f"Invalid line {lineno}: {line}")
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()

        while stack and indent < stack[-1][0]:
            stack.pop()
        if not stack:
            raise ConfigError(f"Invalid nesting at line {lineno}")

        current = stack[-1][1]
        if value == "":
            child: dict[str, Any] = {}
            current[key] = child
            stack.append((indent + 2, child))
            continue

        if value.startswith(('"', "'")) and value.endswith(('"', "'")) and len(value) >= 2:
            value = value[1:-1]
        elif value.lower() in ("true", "false"):
            value = value.lower() == "true"
        else:
            try:
                value = int(value)
            except ValueError:
                pass

        current[key] = value

    return root

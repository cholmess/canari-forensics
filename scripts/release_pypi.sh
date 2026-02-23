#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

python3 - <<'PY'
import shutil, sys
missing = [m for m in ("twine",) if shutil.which(m) is None]
if missing:
    print("warning: missing executables:", ", ".join(missing))
PY

rm -rf build dist *.egg-info canari_forensics.egg-info
python3 - <<'PY'
import setuptools.build_meta as bm
print('building wheel...')
print(bm.build_wheel('dist'))
print('building sdist...')
print(bm.build_sdist('dist'))
PY

if python3 -m twine --version >/dev/null 2>&1; then
  python3 -m twine check dist/*
else
  echo "twine not installed; skipping twine check"
fi

echo
echo "Artifacts ready in dist/:"
ls -lh dist

echo
echo "Upload commands:"
echo "  TestPyPI: python3 -m twine upload --repository testpypi dist/*"
echo "  PyPI:     python3 -m twine upload dist/*"

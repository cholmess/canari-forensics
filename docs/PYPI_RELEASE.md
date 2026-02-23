# PyPI Release

## Prerequisites

- PyPI account with permission for `canari-forensics`
- `TWINE_USERNAME` and `TWINE_PASSWORD` (or API token)
- Python 3.10+

## Build

```bash
./scripts/release_pypi.sh
```

This generates:
- `dist/canari_forensics-<version>.tar.gz`
- `dist/canari_forensics-<version>-py3-none-any.whl`

## Upload

```bash
python3 -m twine upload dist/*
```

Test upload first:

```bash
python3 -m twine upload --repository testpypi dist/*
```

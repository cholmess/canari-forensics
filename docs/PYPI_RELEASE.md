# PyPI Release

## Recommended: Trusted Publisher (GitHub Actions)

Use the workflow `.github/workflows/release-pypi.yml`.
It publishes to PyPI when you push a tag matching `v*` (for example `v0.1.1`).

### 1) Configure Trusted Publisher on PyPI

In PyPI project settings for `canari-forensics`, add a Trusted Publisher:
- Owner: `cholmess`
- Repository: `canari-forensics`
- Workflow: `release-pypi.yml`
- Environment (recommended): `pypi`

### 2) Create and push a release tag

```bash
git tag v0.1.1
git push origin v0.1.1
```

The workflow will:
- build sdist/wheel
- publish to PyPI via OIDC (no API token needed)

## Manual release

```bash
./scripts/release_pypi.sh
python3 -m twine upload dist/*
```

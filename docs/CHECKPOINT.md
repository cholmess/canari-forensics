# Canari Forensics Checkpoint

This repository now supports the full local audit workflow:

1. Parse OTEL JSON and MLflow-style traces.
2. Scan MLflow traces (MLflow client path).
3. Generate findings, evidence JSON, `.bp.json` snapshots, and PDF report.
4. Run staged audits (`audit init`, `audit scan`, `audit report`).
5. Run one-command audit from config (`audit run`).
6. Optional OTLP receiver ingest path with SQLite persistence.

## Reproducible local demo

```bash
./scripts/demo_local_audit.sh
```

Expected artifact directory:

```text
/tmp/canari-demo/.canari/audits/demo-local-otel-audit/
```

Expected files:
- `audit.json`
- `scan-report.json`
- `evidence.json`
- `audit-report.pdf`
- `bp-snapshots/F-0001.bp.json` (or more)

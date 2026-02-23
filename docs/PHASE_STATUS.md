# Canari Forensics Phase Status

## Completed

- Phase 0: OTEL parser core + MLflow native parsing + performance test baseline.
- Phase 1: Databricks/MLflow integration path and CLI scan command.
- Phase 2: Universal OTEL providers and receiver ingest + SQLite persistence.
- Phase 3: Enterprise outputs (evidence JSON, PDF, BreakPoint snapshots).
- Phase 4: Staged audits (`audit init`, `audit scan`, `audit report`).
- Phase 5: Config-driven one-command run (`audit run`).
- Phase 6: Reproducible local demo script and checkpoint docs.
- Phase 7: Packaging metadata + CI workflow.
- Phase 8: Negative validation coverage.
- Phase 9: Typed CLI errors and stable exit codes.
- Phase 10: Version metadata and traceability fields.

## Current capabilities

- Parse OTEL JSON traces and MLflow-style traces.
- Scan Databricks experiment traces through MLflow client integration.
- Generate deterministic findings and produce executive-friendly artifacts.
- Persist and resume audits in `.canari/audits/` workspaces.
- Run full audit workflow from `.canari.yml`.

## Suggested next increments

- Add optional PII pattern tiers and custom pattern packs.
- Add CSV export for findings and SOC workflow integration.
- Add signature/hash for evidence packs.
- Add richer PDF layout (multi-page and sections).

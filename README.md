# canari-forensics
Scan your LLM logs for breaches that already happened.

## Quick start

```bash
# 1) Scan OTEL JSON exports (generic/datadog/honeycomb via --provider)
./canari forensics scan \
  --source otel \
  --provider generic \
  --logs ./otel-traces \
  --file-pattern '*.json' \
  --out ./forensics-scan.json

# 2) Generate enterprise audit outputs
./canari forensics report \
  --scan-report ./forensics-scan.json \
  --client "Acme Corp" \
  --application "AI Gateway" \
  --out-pdf ./audit-report.pdf \
  --out-evidence ./canari-evidence.json \
  --bp-dir ./tests/attacks

# 3) (Optional) Run OTLP receiver mode (real-time ingest)
./canari forensics receive \
  --host 0.0.0.0 \
  --port 4318 \
  --db ./canari-forensics.db
```

## Databricks direct scan

```bash
./canari forensics scan \
  --source databricks \
  --experiment-id 1234567890 \
  --tracking-uri databricks \
  --out ./forensics-scan.json
```

Outputs:
- Scan JSON with normalized conversation turns
- Evidence JSON with findings and metadata
- PDF audit report for executive review
- `.bp.json` snapshots for BreakPoint CI workflows

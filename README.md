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
```

## Staged audit workflow

```bash
# initialize audit workspace
./canari forensics audit init \
  --name "Q1 2026 AI Gateway Audit" \
  --source otel \
  --provider generic \
  --logs ./otel-traces \
  --client "Acme Corp" \
  --application "AI Gateway"

# run scan and report using stored metadata
./canari forensics audit scan --audit-id q1-2026-ai-gateway-audit
./canari forensics audit report --audit-id q1-2026-ai-gateway-audit
```

## Databricks direct scan

```bash
./canari forensics scan \
  --source databricks \
  --experiment-id 1234567890 \
  --tracking-uri databricks \
  --out ./forensics-scan.json
```

## Real-time OTLP receiver

```bash
./canari forensics receive \
  --host 0.0.0.0 \
  --port 4318 \
  --db ./canari-forensics.db
```

Outputs:
- Scan JSON with normalized conversation turns
- Evidence JSON with findings and metadata
- PDF audit report for executive review
- `.bp.json` snapshots for BreakPoint CI workflows

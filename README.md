# canari-forensics
Scan your LLM logs for breaches that already happened.

## Quick start

```bash
# Scan OTEL JSON exports (generic/datadog/honeycomb via --provider)
./canari forensics scan \
  --source otel \
  --provider generic \
  --logs ./otel-traces \
  --file-pattern '*.json' \
  --out ./forensics-report.json

# Scan Databricks/MLflow traces directly
./canari forensics scan \
  --source databricks \
  --experiment-id 1234567890 \
  --tracking-uri databricks \
  --out ./forensics-report.json

# Run OTLP receiver mode (real-time ingest)
./canari forensics receive \
  --host 0.0.0.0 \
  --port 4318 \
  --db ./canari-forensics.db
```

Scan output is JSON with normalized conversation turns. Receiver mode persists turns in SQLite for continuous monitoring pipelines.

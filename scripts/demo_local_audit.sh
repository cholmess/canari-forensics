#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

OUT_BASE="${1:-/tmp/canari-demo}"
AUDIT_NAME="Demo Local OTEL Audit"
AUDIT_ID="demo-local-otel-audit"

rm -rf "$OUT_BASE"
mkdir -p "$OUT_BASE"

cat > "$OUT_BASE/.canari.yml" <<YAML
forensics:
  source: otel
  provider: generic
  logs: $ROOT_DIR/tests/fixtures/otlp_sample.json
  file_pattern: "*.json"
  client: "Demo Client"
  application: "Demo App"
  audit_name: "$AUDIT_NAME"
  tracking_uri: databricks
  max_results: 1000
YAML

(
  cd "$OUT_BASE"
  "$ROOT_DIR/canari" forensics audit run --config .canari.yml
)

echo "Demo completed"
echo "Artifacts: $OUT_BASE/.canari/audits/$AUDIT_ID"

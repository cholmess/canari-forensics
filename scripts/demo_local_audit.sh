#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

OUT_BASE="${1:-/tmp/canari-demo}"
AUDIT_NAME="Demo Local OTEL Audit"
SAMPLE_LOG="$OUT_BASE/demo-otlp.json"

rm -rf "$OUT_BASE"
mkdir -p "$OUT_BASE"

python3 - "$SAMPLE_LOG" <<'PY'
import json
import sys
from datetime import datetime, timedelta, timezone

out_path = sys.argv[1]
now = datetime.now(timezone.utc)
event_time = now - timedelta(days=94)
span_start = event_time - timedelta(seconds=2)

def to_unix_nano(dt: datetime) -> str:
    return str(int(dt.timestamp() * 1_000_000_000))

payload = {
    "resourceSpans": [
        {
            "scopeSpans": [
                {
                    "spans": [
                        {
                            "traceId": "0xdemo94days",
                            "spanId": "0xscan01",
                            "name": "chat completions canari demo",
                            "startTimeUnixNano": to_unix_nano(span_start),
                            "events": [
                                {
                                    "name": "gen_ai.user.message",
                                    "timeUnixNano": to_unix_nano(event_time - timedelta(seconds=1)),
                                    "attributes": [
                                        {"key": "content", "value": {"stringValue": "Need billing debug details."}}
                                    ],
                                },
                                {
                                    "name": "gen_ai.assistant.message",
                                    "timeUnixNano": to_unix_nano(event_time),
                                    "attributes": [
                                        {
                                            "key": "content",
                                            "value": {
                                                "stringValue": "Internal note leaked to user: stripe_live_key=sk_live_9fA2bC3dE4fG5hI6jK7l"
                                            },
                                        }
                                    ],
                                },
                            ],
                        }
                    ]
                }
            ]
        }
    ]
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
PY

cat > "$OUT_BASE/.canari.yml" <<YAML
forensics:
  source: otel
  provider: generic
  logs: $SAMPLE_LOG
  file_pattern: "*.json"
  client: "Demo Client"
  application: "Demo App"
  audit_name: "$AUDIT_NAME"
  tracking_uri: mlflow
  max_results: 1000
YAML

(
  cd "$OUT_BASE"
  "$ROOT_DIR/canari" forensics audit run --config .canari.yml
)

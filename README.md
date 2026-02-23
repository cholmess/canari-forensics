# canari-forensics
Scan your LLM logs for breaches that already happened.

LLM applications can leak internal context through prompt injection
attacks. Your firewall never flags it because the exfiltration looks
exactly like a legitimate API response. Most teams find out weeks
later - if ever.

Canari Forensics scans your existing LLM conversation logs and tells
you definitively whether you have had any successful prompt injection
or credential leakage before you were monitoring. Exact pattern
matching, no classifiers, no false positives. Runs locally in under
a minute. No data leaves your environment.

## Install

```bash
pip install canari-forensics
```

If your environment blocks package installs, you can run directly with `python3 -m canari_forensics ...`.
After install, run `canari ...` directly.

## Quick start

```bash
# 1) Scan OTEL JSON exports (generic/datadog/honeycomb via --provider)
canari forensics scan \
  --source otel \
  --provider generic \
  --logs ./otel-traces \
  --file-pattern '*.json' \
  --out ./forensics-scan.json

# 2) Generate enterprise audit outputs
canari forensics report \
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
canari forensics audit init \
  --name "Q1 2026 AI Gateway Audit" \
  --source otel \
  --provider generic \
  --logs ./otel-traces \
  --client "Acme Corp" \
  --application "AI Gateway"

# run scan and report using stored metadata
canari forensics audit scan --audit-id q1-2026-ai-gateway-audit
canari forensics audit report --audit-id q1-2026-ai-gateway-audit
```

## One-command audit from config

```bash
cp .canari.yml.example .canari.yml
canari forensics audit run --config .canari.yml
```


## Custom pattern packs

```bash
canari forensics report   --scan-report ./forensics-scan.json   --client "Acme Corp"   --application "AI Gateway"   --out-pdf ./audit-report.pdf   --out-evidence ./canari-evidence.json   --bp-dir ./tests/attacks   --patterns-file ./custom_patterns.json
```

The JSON file should contain either `{"patterns": [...]}` or a top-level array, where each pattern has:
`pattern_id`, `name`, `severity`, `confidence`, `kind`, `regex`.

## Local demo checkpoint

```bash
./scripts/demo_local_audit.sh
```

## Real-time OTLP receiver

```bash
canari forensics receive \
  --host 0.0.0.0 \
  --port 4318 \
  --db ./canari-forensics.db
```

Outputs:
- Scan JSON with normalized conversation turns
- Evidence JSON with findings and metadata
- PDF audit report for executive review
- `.bp.json` snapshots for BreakPoint CI workflows

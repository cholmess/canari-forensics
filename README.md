# canari-forensics

[![PyPI package](https://img.shields.io/pypi/v/canari-forensics?label=pypi%20package)](https://pypi.org/project/canari-forensics/)
[![CI](https://github.com/cholmess/canari-forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/cholmess/canari-forensics/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

## Demo

Run the local demo to see Canari Forensics find incidents in sample logs:
```bash
./scripts/demo_local_audit.sh
```

Expected output:

```text
┌─ Scan Complete ───────────────────────────────────────────────
Scanned: 2 turns | 0.00 seconds
Conversations: 1
Scan report: .canari/audits/demo-local-otel-audit/scan-report.json
└───────────────────────────────────────────────────────────────
┏━ Canari Forensics Incident Review ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scanned: 2 turns | 0.00 seconds
INCIDENTS FOUND: 1
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#1 Severity: CRITICAL
Pattern type: real_credential_leak (cred_stripe_live)
Occurred: 94 days ago
Context: ... stripe_live_key=sk_live_...
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Evidence: .canari/audits/demo-local-otel-audit/evidence.json
PDF: .canari/audits/demo-local-otel-audit/audit-report.pdf
BreakPoint snapshots: 1
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
These incidents occurred before you were monitoring.
Canari would have caught them in real time.
```

![Canari demo](https://raw.githubusercontent.com/cholmess/canari-forensics/main/docs/demo.gif)

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
canari forensics report \
  --scan-report ./forensics-scan.json \
  --client "Acme Corp" \
  --application "AI Gateway" \
  --out-pdf ./audit-report.pdf \
  --out-evidence ./canari-evidence.json \
  --bp-dir ./tests/attacks \
  --patterns-file ./custom_patterns.json
```

The JSON file should contain either `{"patterns": [...]}` or a top-level array,
where each pattern has: `pattern_id`, `name`, `severity`, `confidence`, `kind`, `regex`.

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

## Related Tools

- [BreakPoint](https://github.com/cholmess/breakpoint-ai) — catch regressions before you ship
- [Canari](https://github.com/cholmess/canari) — detect attacks in real time
- [Canari Forensics](https://github.com/cholmess/canari-forensics) — audit logs for past breaches

## Maintainer

Maintained by Christopher Holmes Silva.

- X: https://x.com/cholmess
- LinkedIn: https://linkedin.com/in/cholmess

Feedback is welcome from developers shipping LLM applications.

# Operation Audit Base

> A zero-dependency, drop-in **shared audit base** for AI agents — one 16-column contract for every skill's events, dirty-data markers on entry, a computable anomaly engine, bilingual daily/weekly reports with red-flagged anomalies, machine-readable alert JSON, dual-channel query/export, and undoable deletion.
> *(Open-source release; the project was previously known only by an internal codename.)*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![Self-test](https://img.shields.io/badge/selftest-19%2F19%20passing-brightgreen.svg)]()

---

## Why

Every skill in an agent stack makes decisions — allow or deny, clean or block, pass or fail. Without a
single sink, that evidence is scattered and unverifiable. This skill is the **one audit base**: every
event is ingested through a single 16-column contract, dirty data is marked (never silently dropped),
anomalies are computed from JSON rules (never hardcoded), and reports come out bilingual with anomalies
red-flagged for human attention.

**Core principle:** single field contract / zero sensitive values on disk / append-only (undo excepted) /
fully computable.

## Features

- **16-column contract** — one format for every skill's events (`ts … schema_version`); no custom formats.
- **Ingest markers (dirty data never blocks)** — missing required fields → `incomplete` (WARN, not written); unrecognized source → `unverified_source`; conflicting result (DENY but ALLOW for the same actor+target within 60s) → `conflict` (CRIT).
- **Computable anomaly engine** — CRIT / conflict / repeated-deny (same source, ≥3 consecutive denies) / open-hold (hold unclosed > 24h); every threshold in `audit_rules.json`.
- **Bilingual daily + weekly reports** — anomalies red-flagged; open holds listed prominently with ref_id.
- **Alert JSON** — synced on every weekly; also standalone via `export-alerts`; 16 columns + anomaly_type; fingerprints only.
- **Dual-channel interfaces** — `query` (source/severity/date/limit filters, table or CSV) and `export` (md/json/csv); no UI dependency; voice and click share the same CLI.
- **Undoable deletion** — `clean` moves files into the `.undo` zone with a sha256 manifest; `undo --restore` verifies the hash before restoring; last 3 operations kept.
- **Storage separation** — runtime data defaults to `%LOCALAPPDATA%\AuditBase\audit`; `migrate` copies legacy in-package data (source kept, idempotent).
- **Self-test gate** — 19 cases (6 legacy regression + full U1–U7 coverage); delivery requires 100% green.

## Quick start

```bash
# Ingest one 16-column event (markers applied automatically)
python assets/scripts/audit_core.py ingest --event '{"ts":"2026-10-18T00:00:00Z","source":"gatekeeper","event_type":"access.deny","actor":"app-x","action":"SELECT","target":"read_catalog","result":"DENY","severity":"CRIT","rule_id":"fn-not-whitelisted","evidence_hash":"abc123","status":"recorded","schema_version":"1.0"}'

# Daily / weekly report (bilingual, anomalies red-flagged; weekly also writes alert JSON)
python assets/scripts/audit_core.py daily
python assets/scripts/audit_core.py weekly

# Alert JSON (redacted)
python assets/scripts/audit_core.py export-alerts

# Query / export (dual-channel, no UI)
python assets/scripts/audit_core.py query --source gatekeeper --severity CRIT --format csv
python assets/scripts/audit_core.py export --format json --out audit.json

# Undoable delete
python assets/scripts/audit_core.py clean --file <path>
python assets/scripts/audit_core.py undo --list
python assets/scripts/audit_core.py undo --restore <undo_id>

# Migrate legacy in-package data (copy, source kept)
python assets/scripts/audit_core.py migrate

# Self-test gate
python assets/scripts/audit_core.py --selftest
```

`--base-dir` works before or after any subcommand; priority: `--base-dir` > `storage.base_dir` in the
rules JSON > default `%LOCALAPPDATA%\AuditBase\audit`.

## Package layout

```
audit-base/
├── SKILL.md                     # skill spec + contract + lifecycle + red lines + dual-channel
├── README.md
├── LICENSE.md                   # MIT
├── assets/
│   ├── audit_rules.json         # contract / rotation / markers / anomalies / storage / alerts / undo (computable)
│   └── scripts/
│       ├── audit_core.py        # core script (CLI subcommands)
│       └── README.md            # script usage notes
```

## Security boundaries

- **Zero sensitive values on disk** — `evidence_hash` stores SHA256 fingerprints (first 16 chars) only; sensitive fields are recorded by name, never by value.
- **Append-only** — events are never modified; deletion goes through the undo zone (hash-verified restore).
- **Computable** — every threshold, retention period and marker rule lives in `audit_rules.json`; nothing is hardcoded, so every decision can be recomputed.
- **No network, no secrets** — pure standard library, no third-party dependencies, no outbound calls.

## License

MIT — see [LICENSE.md](LICENSE.md).

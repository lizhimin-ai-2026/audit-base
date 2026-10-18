---
name: Operation Audit Base (audit-base)
description: A shared audit base that ingests 16-column contract events from any skill, marks dirty data on entry (incomplete / unverified_source / conflict), runs a computable anomaly engine (CRIT / conflict / repeated-deny / open-hold), generates bilingual daily and weekly reports with red-flagged anomalies, exports machine-readable alert JSON (fingerprints only, zero sensitive values), provides dual-channel query/export interfaces (voice and click, no UI dependency), and supports undoable deletion (hash-verified restore). Default storage %LOCALAPPDATA%\AuditBase\audit with legacy-data migration. Pure Python standard library, zero third-party dependencies, 19-case self-test gate.
version: 2.0.0
---

# Operation Audit Base (audit-base)

## Overview

A **shared audit base** skill: a single sink that records every cloud-function deployment, data access,
code change and secret interception, and produces fully traceable audit reports. **Events from all
skills flow into this base** through one 16-column contract.

**Core principles**: single field contract / zero sensitive values on disk / append-only (undo excepted) /
fully computable (every threshold lives in JSON) / bilingual reports.

## When to use

- Any skill emits an operation event (ingest into the base)
- Daily / weekly audit report generation (bilingual, anomalies red-flagged)
- Machine-readable alert export for push channels (JSON)
- Dual-channel query / export (voice command ≡ click, same CLI, no UI dependency)
- Restoring an accidentally deleted log/report file (undoable delete)

## 16-column field contract (the only accepted format)

```
ts, source, event_type, actor, action, target, result, severity,
rule_id, evidence_hash, ref_id, human_decision, undo_ref, note, status, schema_version
```

| Column | Meaning | Examples |
|---|---|---|
| ts | Event time (UTC ISO) | 2026-10-17T04:00:00Z |
| source | Originating skill | gatekeeper / secret-guardian / deploy-contract |
| event_type | Event type | access.allow / access.deny / secret.found |
| actor | Operator | caller name / scanner / admin |
| action | Action | SELECT / deploy / push |
| target | Target | function name / file path |
| result | Result | ALLOW / DENY / FOUND / CLEAN |
| severity | Severity | INFO / WARN / CRIT |
| rule_id | Rule hit | fn-not-whitelisted / conflict-event |
| evidence_hash | Evidence fingerprint (SHA256, first 16) | never a sensitive value |
| ref_id | Reference (e.g. line L12) | L12 |
| human_decision | Human decision | override / hold / "" |
| undo_ref | Undo reference | undo/<id> / "" |
| note | Note (verbatim exception quote) | human-approved: xxx |
| status | Status | recorded / unverified_source / conflict / pending / closed / resolved / archived |
| schema_version | Contract version | 1.0 |

## Lifecycle

```
Any skill event → ingest (audit_core.py ingest, three U2 markers)
     → event log (<base>/events/events_<quarter>.csv)
     → anomaly engine (CRIT / conflict / repeated-deny / open-hold, all thresholds in JSON)
     → daily / weekly report (<base>/reports/, bilingual, anomalies red-flagged)
     → alert JSON (export-alerts, fingerprints only)
     → quarterly rotation + archive (<base>/archive/, 12-month retention configurable, undoable)
```

Default storage root: `%LOCALAPPDATA%\AuditBase\audit` (subdirs events / reports / archive / .undo);
override with `--base-dir` or `storage.base_dir` in the rules JSON.

## Red lines

1. **Single field contract**: every event must align to the 16 columns; no custom formats.
2. **Zero sensitive values on disk**: evidence_hash stores fingerprints only; responses with sensitive fields record field names only.
3. **Append-only** (undo excepted): events are only appended, never modified.
4. **Undoable deletion (the only exception)**: `clean` moves files into the `.undo` zone and registers a manifest (with sha256); `undo --restore` verifies the hash before restoring; only the last 3 operations are kept.
5. **Computable**: all thresholds / whitelists / rules live in `audit_rules.json`; no hardcoding.

## Rule file

- `assets/audit_rules.json`: 16-column contract / rotation / retention / report languages / **ingest_markers / anomaly_rules / storage / alerts / undo / daily_report** (all computable)
- `assets/scripts/audit_core.py`: ingest + anomaly engine + daily/weekly + alerts + query/export + undoable delete + migration
- Runtime data (outside the package by default): `%LOCALAPPDATA%\AuditBase\audit\{events,reports,archive,.undo}`

## Event ingest format (any skill → base)

| Source | event_type | Example |
|---|---|---|
| gatekeeper | access.allow / access.deny | target=function name |
| secret-guardian | secret.found / secret.blocked | target=file path |
| deploy-contract | deploy.allow / deploy.deny / deploy.override | target=function name |
| compliance | content.pass / content.block | target=content type |
| cross-border | compliance.check / compliance.risk | target=region |

**Markers on ingest (dirty data never blocks)**:

| Condition | Marker | Severity | Original event |
|---|---|---|---|
| Missing required fields | incomplete-event | WARN | not written |
| Unrecognized source (not in ingest_sources) | unverified-source | WARN | written + status=unverified_source |
| Conflicting result (DENY but ALLOW for same actor+target within 60s) | conflict-event | CRIT | written + status=conflict |

## Script spec

- Python 3.11+ standard library (no third-party dependencies)
- `ingest --event <json>`: ingest one event (markers), append-only
- `daily [--date D]`: bilingual daily report (red-flagged anomalies)
- `weekly [--end D]`: bilingual weekly report (anomaly engine) + synced alert JSON
- `rotate [--archive-months N]`: quarterly rotation/archive (undoable)
- `export-alerts [--date-from D] [--date-to D] [--out F]`: alert JSON (16 columns + anomaly_type, redacted)
- `query [--source S] [--severity V] [--date-from D] [--date-to D] [--limit N] [--format table|csv]`: query
- `export --format md|json|csv [--out F]`: export report (three formats)
- `clean --file <path>`: safe delete into the undo zone
- `undo --list | --restore <undo_id>`: hash-verified restore
- `migrate`: copy legacy in-package data to the new storage (source kept, idempotent)
- `--base-dir`: storage root (before or after the subcommand; priority: --base-dir > rules.storage.base_dir > default %LOCALAPPDATA%\AuditBase\audit)
- `--selftest`: 19-case gate (6 legacy regression + full U1–U7 coverage); delivery requires 100% green

## Anomaly engine

| Type | Rule (thresholds in anomaly_rules) | Report |
|---|---|---|
| crit | severity=CRIT | red-flagged [CRIT] |
| conflict | rule_id=conflict-event | red-flagged [conflict] |
| repeated-deny | consecutive denies from the same source ≥ 3 (event_types configurable) | red-flagged [repeated-deny] |
| open-hold | human_decision=hold and unclosed > 24h (status not in closed/resolved/archived) | red-flagged open-holds section |

## Alert JSON

- Synced on every `weekly`; also available standalone via `export-alerts`
- Structure: `{generated_at, schema_version, count, alerts:[{16 columns…, anomaly_type}]}`
- Redaction: evidence_hash fingerprint only (≤16 chars), no sensitive plaintext

## Dual-channel interfaces

- **Query**: `query` filters by source / severity / date range / limit; table or CSV output
- **Export**: `export` supports md / json / csv with optional date range and output path
- Voice and click channels share the same CLI (single execution出口); see the dual-channel section below

## Undoable deletion

- `clean --file <path>`: moves the file into `<base>/.undo/<undo_id>/`, manifest registers original path / backup path / sha256 / reason
- `undo --list`: list pending items; `undo --restore <undo_id>`: verify hash, then move back
- Only the last 3 operations kept (`undo.keep_last` configurable); older backups are truly deleted

## Storage & migration

- Default: `%LOCALAPPDATA%\AuditBase\audit` (runtime data separated from the code package)
- Migration: `migrate` copies legacy in-package `assets/{logs,reports,archive}` into the new storage (copy, source kept, existing files skipped, idempotent)

## Dual-channel trigger spec (voice + click)

- **Wake word**: the skill name; voice commands: "audit, weekly report / query logs / export audit" (weekly / query / export)
- **Click entry**: security center → operation audit → generate weekly / query logs / export
- **Unified authorization**: voice confirm ≡ click confirm (single execution outlet); report generation / rotation / query / export are read-only and allowed by default
- **Undoable actions**: after `clean`, either channel can `undo` restore (hash-verified), fully logged
- **State sync**: this base is the status-sync hub for all skills (16-column contract); both channels see events in real time
- **Degradation**: voice-channel errors are logged only, click is the fallback; both down → read-only default (no report, no rotation)

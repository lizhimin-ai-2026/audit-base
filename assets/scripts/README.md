#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Operation Audit Base — script notes

audit_core.py is the shared audit base core (see ../README.md).

Usage (--base-dir works before or after the subcommand):
  ingest --event <json>            ingest one 16-column event (three markers, schema_version auto-filled)
  daily [--date D]                 bilingual daily report (anomalies red-flagged)
  weekly [--end D]                 bilingual weekly report (anomaly engine) + synced alert JSON
  rotate [--archive-months N]      quarterly rotation/archive (12-month retention default, undoable)
  export-alerts [--date-from D] [--date-to D] [--out F]  export alert JSON (redacted)
  query [--source S] [--severity V] [--date-from D] [--date-to D] [--limit N] [--format table|csv]  query
  export --format md|json|csv [--out F]  export report (three formats)
  clean --file <path>              safe delete into the undo zone
  undo --list | --restore <undo_id>  hash-verified restore
  migrate                          copy legacy in-package data to the new storage (source kept)
  --selftest                      19-case gate (6 legacy regression + full U1-U7 coverage)

Host integration:
  - Any skill calls ingest after emitting an event (unified 16 columns).
  - The red-flagged "Anomalies" section of weekly_<date>.md feeds alert push channels.
  - Events are append-only; rotation moves old quarters into archive (no data deleted);
    clean deletions go through the undo zone and are restorable.
  - Redaction red line: note/evidence_hash must never carry secret plaintext (fingerprints or field names only).
  - Default storage %LOCALAPPDATA%\AuditBase\audit (events/reports/archive/.undo), separated from the code package.
"""

import os

if __name__ == "__main__":
    print(__doc__)
    print(f"Rules file: {os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'audit_rules.json')}")

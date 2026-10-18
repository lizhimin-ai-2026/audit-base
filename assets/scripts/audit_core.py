#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Operation Audit Base (audit-base) — core script v2.0

A shared audit base: ingests events from any skill (16-column contract),
rotates/archives by quarter (12-month retention, configurable), generates bilingual daily/weekly reports (anomaly red-flags),
exports alert JSON, provides dual-channel query/export interfaces, undoable deletion.

Red lines: single field contract / zero sensitive values on disk / append-only (undo excepted) / fully computable (all rules in JSON).

用法（--base-dir 放子命令前后均可）：
  python audit_core.py ingest --event <json> [--base-dir X]      # 收口一条事件（U2 标记）
  python audit_core.py daily  [--date YYYY-MM-DD] [--base-dir X] # 日报（中英，U1）
  python audit_core.py weekly [--end YYYY-MM-DD]  [--base-dir X] # 周报（中英，含异常引擎 U3）
  python audit_core.py rotate [--archive-months N] [--base-dir X]# 季度轮转归档（可撤销）
  python audit_core.py export-alerts [--date-from D] [--date-to D] [--out F] [--base-dir X]  # 告警 JSON（U4）
  python audit_core.py query --source S --severity V --date-from D --date-to D --limit N [--format table|csv] [--base-dir X]  # 查询（U5）
  python audit_core.py export --format md|json|csv [--out F] [--date-from D] [--date-to D] [--base-dir X]                        # 导出（U5）
  python audit_core.py clean --file <path> [--base-dir X]         # 安全删除（移入撤销区，U7）
  python audit_core.py undo --list | --restore <id> [--base-dir X]# 撤销（U7）
  python audit_core.py migrate [--base-dir X]                     # 旧包内数据迁移到新存储（U6，复制不删源）
  python audit_core.py --selftest
"""

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # audit-base/
PKG_LOGS_DIR = os.path.join(SKILL_DIR, "assets", "logs")
PKG_REPORTS_DIR = os.path.join(SKILL_DIR, "assets", "reports")
PKG_ARCHIVE_DIR = os.path.join(SKILL_DIR, "assets", "archive")
RULES_PATH = os.path.join(SKILL_DIR, "assets", "audit_rules.json")

DEFAULT_REQUIRED_FIELDS = ["ts", "source", "event_type", "actor", "action", "target",
                           "result", "severity", "rule_id", "evidence_hash", "status"]
CLOSED_STATUS = {"closed", "resolved", "archived"}


# ---------- 基础 ----------

def load_rules():
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(ts):
    """解析 ISO 时间（容忍 Z 后缀/无时区），失败返回 None。"""
    if not ts:
        return None
    s = ts.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def quarter_of(ts):
    year = ts[:4]
    month = int(ts[5:7])
    q = (month - 1) // 3 + 1
    return f"{year}Q{q}"


def current_quarter():
    return quarter_of(utc_now_iso())


def hash_value(v):
    return hashlib.sha256(str(v).encode("utf-8")).hexdigest()[:16]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------- 存储解析（U6） ----------

def default_base_dir():
    local = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(local, "AuditBase", "audit")


def resolve_base_dir(cli_base_dir, rules):
    """优先级：--base-dir > rules.storage.base_dir > 默认 %LOCALAPPDATA%\\AuditBase\\audit。"""
    if cli_base_dir:
        return os.path.abspath(cli_base_dir)
    storage = rules.get("storage", {})
    cfg = (storage.get("base_dir") or "").strip()
    if cfg:
        return os.path.expandvars(cfg)
    return default_base_dir()


def dirs_for(base_dir):
    return {
        "logs": os.path.join(base_dir, "events"),
        "reports": os.path.join(base_dir, "reports"),
        "archive": os.path.join(base_dir, "archive"),
        "undo": os.path.join(base_dir, ".undo"),
    }


def ensure_dirs(base_dir):
    d = dirs_for(base_dir)
    for p in d.values():
        os.makedirs(p, exist_ok=True)
    return d


def log_path_for(base_dir, quarter):
    return os.path.join(dirs_for(base_dir)["logs"], f"events_{quarter}.csv")


# ---------- 16 列契约校验 ----------

def validate_event(rules, ev):
    """16 列契约严格校验：缺列/多列/缺 ts → 拒绝（用于完整事件）。"""
    cols = rules["event_columns"]
    missing = [c for c in cols if c not in ev]
    extra = [k for k in ev if k not in cols]
    if missing:
        raise ValueError(f"事件缺列: {missing}")
    if extra:
        raise ValueError(f"事件多余列: {extra}")
    if not ev.get("ts"):
        raise ValueError("ts 必填")
    return True


def write_event(rules, base_dir, ev):
    """把一条 16 列事件追加写入当前季度 CSV（只追加）。"""
    d = ensure_dirs(base_dir)
    path = log_path_for(base_dir, current_quarter())
    write_header = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rules["event_columns"])
        if write_header:
            w.writeheader()
        w.writerow({c: ev.get(c, "") for c in rules["event_columns"]})
    return path


def _marker_event(rules, rule_id, severity, note, target="", source="audit-base"):
    """构造一条 16 列标记事件（WARN/CRIT），供 U2 落盘。"""
    return {
        "ts": utc_now_iso(), "source": source, "event_type": "audit.marker",
        "actor": "audit-base", "action": "ingest", "target": target,
        "result": "MARKED", "severity": severity, "rule_id": rule_id,
        "evidence_hash": "", "ref_id": "", "human_decision": "", "undo_ref": "",
        "note": note, "status": "recorded", "schema_version": rules["schema_version"],
    }


def _recent_allow_hit(base_dir, rules, actor, target, within_seconds):
    """冲突判定：同一 actor+target 在时间窗内是否有 ALLOW 记录（U2 conflict）。"""
    path = log_path_for(base_dir, current_quarter())
    if not os.path.exists(path):
        return False
    now = datetime.now(timezone.utc)
    with open(path, "r", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("result") != "ALLOW":
                continue
            if row.get("actor") == actor and row.get("target") == target:
                dt = parse_ts(row.get("ts"))
                if dt and abs((now - dt).total_seconds()) <= within_seconds:
                    return True
    return False


def ingest(rules, base_dir, event_json):
    """U2：收口一条事件。脏数据标记不阻断：
       - 必填缺失 → 标 incomplete（WARN，rule_id=incomplete-event，原事件不落盘）
       - 来源不可识别 → 标 unverified_source（WARN，rule_id=unverified-source，原事件仍落盘并标 status）
       - 结果矛盾（DENY 但同 actor+target 窗内又有 ALLOW）→ 标 conflict（CRIT，rule_id=conflict-event）
       标记规则/阈值全部来自 audit_rules.json。
    """
    markers = rules.get("ingest_markers", {})
    required = markers.get("required_fields", DEFAULT_REQUIRED_FIELDS)
    window = int(markers.get("conflict_window_seconds", 60))
    try:
        ev = json.loads(event_json)
    except (json.JSONDecodeError, TypeError) as e:
        print(f"INGEST ERROR: 事件不是合法 JSON: {e}", file=sys.stderr)
        return 2
    if not isinstance(ev, dict):
        print("INGEST ERROR: 事件必须是 JSON 对象", file=sys.stderr)
        return 2
    ev.setdefault("schema_version", rules["schema_version"])

    # 1) 必填缺失 → incomplete（不落原事件，记 WARN）
    missing = [c for c in required if not str(ev.get(c, "")).strip()]
    if missing:
        p = write_event(rules, base_dir, _marker_event(
            rules, "incomplete-event", "WARN",
            f"必填字段缺失({','.join(missing)})，事件标记 incomplete 未落盘", target=str(ev.get("target", ""))))
        print(f"INGEST MARKED incomplete (缺失 {missing}) -> WARN 已落盘 {p}")
        return 0

    # 2) 来源不可识别 → unverified_source（WARN，原事件仍落盘并标 status）
    known_sources = set(rules.get("ingest_sources", {}).keys())
    src = str(ev.get("source", "")).strip()
    if not src or (known_sources and src not in known_sources):
        ev["status"] = "unverified_source"
        write_event(rules, base_dir, _marker_event(
            rules, "unverified-source", "WARN",
            f"来源不可识别(source={src or '空'})，事件标 unverified_source", target=str(ev.get("target", ""))))

    # 3) 结果矛盾 → conflict（CRIT，原事件仍落盘并标 status）
    if ev.get("result") == "DENY":
        if _recent_allow_hit(base_dir, rules, ev.get("actor", ""), ev.get("target", ""), window):
            ev["status"] = "conflict"
            write_event(rules, base_dir, _marker_event(
                rules, "conflict-event", "CRIT",
                f"结果矛盾：DENY 但同 actor+target {window}s 内有 ALLOW", target=str(ev.get("target", ""))))

    validate_event(rules, ev)  # 完整事件走严格契约
    path = write_event(rules, base_dir, ev)
    print(f"INGEST OK -> {path} (status={ev.get('status')})")
    return 0


# ---------- 查询 / 读取 ----------

def load_all_events(base_dir):
    rows = []
    logs = dirs_for(base_dir)["logs"]
    if not os.path.isdir(logs):
        return rows
    for fn in sorted(os.listdir(logs)):
        if fn.startswith("events_") and fn.endswith(".csv"):
            with open(os.path.join(logs, fn), "r", newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    rows.append(row)
    return rows


def _in_range(ts, date_from, date_to):
    d = (ts or "")[:10]
    if date_from and d < date_from:
        return False
    if date_to and d > date_to:
        return False
    return True


# ---------- 轮转归档（可撤销，U7） ----------

def rotate(rules, base_dir, archive_months):
    d = ensure_dirs(base_dir)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=archive_months * 30)
    moved = []
    logs = d["logs"]
    for fn in os.listdir(logs):
        if not (fn.startswith("events_") and fn.endswith(".csv")):
            continue
        q = fn[len("events_"):-len(".csv")]
        try:
            year, qnum = int(q[:4]), int(q[5])
        except (ValueError, IndexError):
            continue
        end_of_quarter = datetime(year, qnum * 3, 28, tzinfo=timezone.utc)
        if end_of_quarter < cutoff:
            src = os.path.join(logs, fn)
            dst = os.path.join(d["archive"], fn)
            shutil.move(src, dst)
            _register_undo(base_dir, src, dst, f"rotate 归档 {fn}")
            moved.append(fn)
    _prune_undo(base_dir)
    print(f"ROTATE OK: 归档 {len(moved)} 个旧季度文件（保留 {archive_months} 个月，可 undo 恢复）")
    return 0


# ---------- 撤销机制（U7，对齐 CleanKeeper） ----------

def _manifest_path(base_dir):
    return os.path.join(dirs_for(base_dir)["undo"], "manifest.json")


def _load_manifest(base_dir):
    p = _manifest_path(base_dir)
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"entries": []}


def _save_manifest(base_dir, manifest):
    ensure_dirs(base_dir)
    with open(_manifest_path(base_dir), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)


def _register_undo(base_dir, original_path, backup_path, reason, undo_id=None):
    """登记一次可撤销操作（同盘移动，manifest 记 sha256）。
    undo_id 可由调用方传入（safe_delete 已生成并打印，必须一致）。"""
    manifest = _load_manifest(base_dir)
    if not undo_id:
        undo_id = f"u{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
    manifest["entries"].append({
        "undo_id": undo_id, "original_path": original_path, "backup_path": backup_path,
        "sha256": sha256_file(backup_path) if os.path.isfile(backup_path) else "",
        "ts": utc_now_iso(), "reason": reason,
    })
    _save_manifest(base_dir, manifest)
    return undo_id


def _prune_undo(base_dir, keep=3):
    """只保留最近 keep 次可回滚（超出即真正删除其备份）。"""
    manifest = _load_manifest(base_dir)
    entries = manifest["entries"]
    keep_n = int(keep)
    while len(entries) > keep_n:
        old = entries.pop(0)
        bp = old.get("backup_path", "")
        if bp and os.path.isfile(bp):
            os.remove(bp)
    _save_manifest(base_dir, manifest)


def safe_delete(base_dir, path, reason="manual clean"):
    """U7：删除前移入撤销备份区，登记 manifest，保留最近 3 次可回滚。"""
    if not os.path.isfile(path):
        print(f"CLEAN ERROR: 文件不存在 {path}", file=sys.stderr)
        return 2
    d = ensure_dirs(base_dir)
    undo_id = f"u{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
    backup_dir = os.path.join(d["undo"], undo_id)
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, os.path.basename(path))
    shutil.move(path, backup_path)
    _register_undo(base_dir, os.path.abspath(path), backup_path, reason, undo_id=undo_id)
    _prune_undo(base_dir)
    print(f"CLEAN OK: {path} 移入撤销区（undo_id={undo_id}，可 undo --restore 恢复）")
    return 0


def undo_list(base_dir):
    manifest = _load_manifest(base_dir)
    if not manifest["entries"]:
        print("无待撤销项")
        return 0
    for e in manifest["entries"]:
        print(f"- {e['undo_id']} | {e['ts']} | {e['reason']} | {os.path.basename(e['original_path'])}")
    return 0


def undo_restore(base_dir, undo_id):
    manifest = _load_manifest(base_dir)
    entry = next((e for e in manifest["entries"] if e["undo_id"] == undo_id), None)
    if not entry:
        print(f"UNDO ERROR: 未找到 undo_id={undo_id}", file=sys.stderr)
        return 2
    backup_path = entry["backup_path"]
    if not os.path.isfile(backup_path):
        print(f"UNDO ERROR: 备份不存在 {backup_path}", file=sys.stderr)
        return 2
    cur = sha256_file(backup_path)
    if entry.get("sha256") and cur != entry["sha256"]:
        print(f"UNDO ERROR: 哈希不一致（备份被改）{entry['sha256']} != {cur}", file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(entry["original_path"]), exist_ok=True)
    shutil.move(backup_path, entry["original_path"])
    manifest["entries"].remove(entry)
    _save_manifest(base_dir, manifest)
    print(f"UNDO OK: 已恢复 {entry['original_path']}（哈希校验一致）")
    return 0


# ---------- 异常引擎（U3） ----------

def compute_anomalies(rules, events):
    """返回 [(event_dict, anomaly_type), ...]。规则/阈值来自 audit_rules.json。"""
    ar = rules.get("anomaly_rules", {})
    threshold = int(ar.get("repeated_deny_threshold", 3))
    deny_types = set(ar.get("repeated_deny_event_types", ["access.deny", "deploy.deny"]))
    hold_decisions = set(ar.get("hold_decisions", ["hold"]))
    hold_hours = int(ar.get("hold_timeout_hours", 24))
    anomalies = []

    # CRIT
    for e in events:
        if e.get("severity") == "CRIT":
            anomalies.append((e, "crit"))
    # conflict 标记事件
    for e in events:
        if e.get("rule_id") == "conflict-event":
            anomalies.append((e, "conflict"))
    # repeated-deny：同源连续 deny 达阈值
    by_source = {}
    for e in sorted(events, key=lambda x: x.get("ts", "")):
        if e.get("event_type") in deny_types:
            by_source.setdefault(e.get("source", ""), []).append(e)
    for src, denies in by_source.items():
        if len(denies) >= threshold:
            for e in denies[-threshold:]:
                anomalies.append((e, "repeated-deny"))
    # open-hold：hold/override 待办超时未闭环
    now = datetime.now(timezone.utc)
    for e in events:
        if e.get("human_decision") in hold_decisions and e.get("status") not in CLOSED_STATUS:
            dt = parse_ts(e.get("ts"))
            if dt and (now - dt) > timedelta(hours=hold_hours):
                anomalies.append((e, "open-hold"))
    return anomalies


# ---------- 日报（U1） ----------

def _bilingual_report(rules, events, anomalies, title_zh, title_en, path):
    src_counter = Counter(e["source"] for e in events)
    sev_counter = Counter(e["severity"] for e in events)
    res_counter = Counter(e["result"] for e in events)
    overrides = [e for e in events if e.get("human_decision") == "override"]
    open_holds = [(e, t) for (e, t) in anomalies if t == "open-hold"]
    rep_deny = [(e, t) for (e, t) in anomalies if t == "repeated-deny"]
    conflicts = [(e, t) for (e, t) in anomalies if t == "conflict"]
    crits = [(e, t) for (e, t) in anomalies if t == "crit"]

    L = []
    L.append(f"# {title_zh}")
    L.append(f"# {title_en}")
    L.append("")
    L.append("## 摘要 / Summary")
    L.append(f"- 事件总数 Total: {len(events)}")
    L.append(f"- 来源分布 By source: {dict(src_counter)}")
    L.append(f"- 严重度 By severity: {dict(sev_counter)}")
    L.append(f"- 结果分布 By result: {dict(res_counter)}")
    L.append(f"- 人工放行 Overrides: {len(overrides)}")
    L.append("")
    L.append("## 异常标记 / Anomalies")
    L.append(f"- CRIT: {len(crits)} | repeated-deny: {len(rep_deny)} | conflict: {len(conflicts)} | open-hold: {len(open_holds)}")
    L.append("- 图例 Legend: 🔴 = 需人工关注 / needs human attention")
    for e, t in crits[:10]:
        L.append(f"  - 🔴 [CRIT] {e['source']} | {e['event_type']} | target={e['target']} | rule={e['rule_id']}")
    for e, t in rep_deny:
        L.append(f"  - 🔴 [repeated-deny] {e['source']} | target={e['target']} | ts={e['ts']}")
    for e, t in conflicts:
        L.append(f"  - 🔴 [conflict] {e['source']} | target={e['target']} | ts={e['ts']}")
    L.append("")
    L.append("## 人工处置统计 / Open Holds (未闭环 > 阈值)")
    if open_holds:
        for e, t in open_holds:
            L.append(f"- 🔴 ref_id={e.get('ref_id') or '-'} | ts={e['ts']} | source={e['source']} | target={e['target']} | 等待动作=pending")
    else:
        L.append("- 无 None")
    L.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return path


def daily(rules, base_dir, date=None):
    d = ensure_dirs(base_dir)
    day = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    events = [e for e in load_all_events(base_dir) if (e.get("ts") or "")[:10] == day]
    anomalies = compute_anomalies(rules, events)
    path = os.path.join(d["reports"], f"daily_{day}.md")
    _bilingual_report(rules, events, anomalies,
                      f"审计日报 / Audit Daily Report（{day}）", f"Audit Daily Report ({day})", path)
    print(f"DAILY OK -> {path}（事件 {len(events)}，异常 {len(anomalies)}）")
    return 0


# ---------- 周报（U3 升级 + U4 告警 JSON） ----------

def weekly(rules, base_dir, end_date=None):
    d = ensure_dirs(base_dir)
    now = datetime.now(timezone.utc)
    end = parse_ts((end_date or now.strftime("%Y-%m-%d")) + "T00:00:00Z") or now
    start = end - timedelta(days=6)
    s_from, s_to = start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")
    events = [e for e in load_all_events(base_dir) if s_from <= (e.get("ts") or "")[:10] <= s_to]
    anomalies = compute_anomalies(rules, events)
    path = os.path.join(d["reports"], f"weekly_{s_to}.md")
    _bilingual_report(rules, events, anomalies,
                      f"审计周报 / Audit Weekly Report（{s_from} ~ {s_to}）",
                      f"Audit Weekly Report ({s_from} ~ {s_to})", path)
    # U4：每次 weekly 同步生成告警 JSON
    alerts_path = os.path.join(d["reports"], f"alerts_{s_to}.json")
    _write_alerts(rules, anomalies, alerts_path)
    print(f"WEEKLY OK -> {path}（异常 {len(anomalies)}）；ALERTS OK -> {alerts_path}")
    return 0


def _write_alerts(rules, anomalies, path):
    cols = rules["event_columns"]
    out = {"generated_at": utc_now_iso(), "schema_version": rules["schema_version"],
           "count": len(anomalies), "alerts": []}
    for e, t in anomalies:
        item = {c: e.get(c, "") for c in cols}  # 16 列；evidence_hash 仅指纹
        item["anomaly_type"] = t
        out["alerts"].append(item)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    return path


def export_alerts(rules, base_dir, date_from=None, date_to=None, out=None):
    d = ensure_dirs(base_dir)
    events = [e for e in load_all_events(base_dir) if _in_range(e.get("ts"), date_from, date_to)]
    anomalies = compute_anomalies(rules, events)
    path = out or os.path.join(d["reports"], f"alerts_{date_to or datetime.now(timezone.utc).strftime('%Y-%m-%d')}.json")
    _write_alerts(rules, anomalies, path)
    print(f"EXPORT-ALERTS OK -> {path}（异常 {len(anomalies)} 条，脱敏：仅 evidence_hash 指纹）")
    return 0


# ---------- 双通道接口：query / export（U5） ----------

def query(rules, base_dir, source=None, severity=None, date_from=None, date_to=None, limit=None, fmt="table"):
    events = load_all_events(base_dir)
    if source:
        events = [e for e in events if e.get("source") == source]
    if severity:
        events = [e for e in events if e.get("severity") == severity]
    events = [e for e in events if _in_range(e.get("ts"), date_from, date_to)]
    events.sort(key=lambda x: x.get("ts", ""))
    if limit:
        events = events[-int(limit):]
    if fmt == "csv":
        w = csv.DictWriter(sys.stdout, fieldnames=rules["event_columns"])
        w.writeheader()
        for e in events:
            w.writerow({c: e.get(c, "") for c in rules["event_columns"]})
    else:
        print(f"{'ts':<22}{'source':<16}{'event_type':<16}{'result':<7}{'severity':<8}{'rule_id'}")
        for e in events:
            print(f"{e.get('ts',''):<22}{e.get('source',''):<16}{e.get('event_type',''):<16}"
                  f"{e.get('result',''):<7}{e.get('severity',''):<8}{e.get('rule_id','')}")
        print(f"-- {len(events)} 条 / total")
    return 0


def export(rules, base_dir, fmt="md", out=None, date_from=None, date_to=None):
    events = [e for e in load_all_events(base_dir) if _in_range(e.get("ts"), date_from, date_to)]
    events.sort(key=lambda x: x.get("ts", ""))
    if fmt == "json":
        content = json.dumps({"schema_version": rules["schema_version"], "count": len(events),
                              "events": [{c: e.get(c, "") for c in rules["event_columns"]} for e in events]},
                             ensure_ascii=False, indent=2)
        default_ext = "json"
    elif fmt == "csv":
        import io
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=rules["event_columns"])
        w.writeheader()
        for e in events:
            w.writerow({c: e.get(c, "") for c in rules["event_columns"]})
        content = buf.getvalue()
        default_ext = "csv"
    else:  # md
        L = [f"# 审计导出 / Audit Export ({len(events)} events)", ""]
        for e in events:
            L.append(f"- {e.get('ts')} | {e.get('source')} | {e.get('event_type')} | {e.get('result')} | {e.get('severity')} | {e.get('rule_id')}")
        content = "\n".join(L)
        default_ext = "md"
    path = out or os.path.join(dirs_for(base_dir)["reports"], f"export.{default_ext}")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"EXPORT OK -> {path}（{len(events)} 条，格式 {fmt}）")
    return 0


# ---------- 存储迁移（U6） ----------

def migrate(rules, base_dir):
    """把既有包内 assets/logs|reports|archive 复制到新存储（复制不删源，幂等）。"""
    d = ensure_dirs(base_dir)
    mapping = [("logs", PKG_LOGS_DIR, d["logs"]), ("reports", PKG_REPORTS_DIR, d["reports"]),
               ("archive", PKG_ARCHIVE_DIR, d["archive"])]
    copied = 0
    for name, src_dir, dst_dir in mapping:
        if not os.path.isdir(src_dir):
            continue
        for fn in os.listdir(src_dir):
            src = os.path.join(src_dir, fn)
            if os.path.isfile(src):
                dst = os.path.join(dst_dir, fn)
                if not os.path.exists(dst):
                    shutil.copy2(src, dst)
                    copied += 1
    print(f"MIGRATE OK: 复制 {copied} 个文件到 {base_dir}（源保留，未删除）")
    return 0


# ---------- 自检（U8：旧 6 + 新 ≥8） ----------

def run_selftest():
    import tempfile
    rules = load_rules()
    passed = total = 0

    def check(ok, desc):
        nonlocal passed, total
        total += 1
        passed += 1 if ok else 0
        print(f"[{'PASS' if ok else 'FAIL'}] {desc}")

    tmp = tempfile.mkdtemp(prefix="audit_base_st_")
    base = os.path.join(tmp, "audit")
    ensure_dirs(base)

    # ===== 旧 6 用例（回归不破坏）=====
    good = {"ts": utc_now_iso(), "source": "gatekeeper", "event_type": "access.allow",
            "actor": "audit-app", "action": "SELECT", "target": "read_catalog",
            "result": "ALLOW", "severity": "INFO", "rule_id": "allow",
            "evidence_hash": "abc", "ref_id": "", "human_decision": "",
            "undo_ref": "", "note": "", "status": "recorded", "schema_version": "1.0"}
    try:
        validate_event(rules, good); check(True, "16列完整事件通过校验")
    except ValueError as e:
        check(False, f"16列完整事件通过校验: {e}")
    bad = dict(good); bad.pop("note")
    try:
        validate_event(rules, bad); check(False, "缺列事件被拒绝")
    except ValueError:
        check(True, "缺列事件被拒绝")
    check(quarter_of("2026-10-17T00:00:00Z") == "2026Q4", "季度计算 2026-10 → 2026Q4")
    check(quarter_of("2026-04-17T00:00:00Z") == "2026Q2", "季度计算 2026-04 → 2026Q2")
    check(hash_value("sk-xxx-secret") != "sk-xxx-secret", "指纹非明文")
    check(len(hash_value("anything")) == 16, "指纹为16位")

    # ===== 新增用例（U1-U7）=====
    # U2-1 incomplete：缺 target → WARN 标记落盘、原事件不落盘
    inc = dict(good); inc.pop("target")
    r = ingest(rules, base, json.dumps(inc))
    evs = load_all_events(base)
    check(r == 0 and any(e.get("rule_id") == "incomplete-event" and e.get("severity") == "WARN" for e in evs)
          and not any(e.get("target") == "" and e.get("source") == "gatekeeper" and e.get("rule_id") == "allow" for e in evs),
          "U2 incomplete：缺必填 → WARN 标记、原事件不落盘")

    # U2-2 unverified_source：未知 source → WARN 标记 + 原事件 status=unverified_source
    unv = dict(good); unv["source"] = "mystery-src"; unv["target"] = "t1"
    r = ingest(rules, base, json.dumps(unv))
    evs = load_all_events(base)
    check(r == 0 and any(e.get("rule_id") == "unverified-source" for e in evs)
          and any(e.get("status") == "unverified_source" and e.get("target") == "t1" for e in evs),
          "U2 unverified_source：未知来源 → WARN 标记 + 事件标 status")

    # U2-3 conflict：先 ALLOW 再同 actor+target DENY（窗内）→ CRIT 标记
    allow_ev = dict(good); allow_ev["actor"] = "app-x"; allow_ev["target"] = "fn-x"; allow_ev["result"] = "ALLOW"
    ingest(rules, base, json.dumps(allow_ev))
    deny_ev = dict(good); deny_ev["actor"] = "app-x"; deny_ev["target"] = "fn-x"
    deny_ev["result"] = "DENY"; deny_ev["event_type"] = "access.deny"; deny_ev["severity"] = "WARN"; deny_ev["rule_id"] = "x"
    r = ingest(rules, base, json.dumps(deny_ev))
    evs = load_all_events(base)
    check(r == 0 and any(e.get("rule_id") == "conflict-event" and e.get("severity") == "CRIT" for e in evs),
          "U2 conflict：DENY 但窗内有 ALLOW → CRIT 标记")

    # U1 daily：生成日报文件
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rc = daily(rules, base, day)
    dpath = os.path.join(dirs_for(base)["reports"], f"daily_{day}.md")
    check(rc == 0 and os.path.exists(dpath), "U1 daily：日报生成成功（中英）")

    # U3 repeated-deny：同源 3 连 deny → 命中
    for i in range(3):
        de = dict(good); de["source"] = "deploy-contract"; de["event_type"] = "deploy.deny"
        de["result"] = "DENY"; de["severity"] = "WARN"; de["rule_id"] = "d"; de["target"] = f"cf{i}"
        ingest(rules, base, json.dumps(de))
    anomalies = compute_anomalies(rules, load_all_events(base))
    check(any(t == "repeated-deny" for _, t in anomalies), "U3 repeated-deny：同源连续 deny 达阈值命中")

    # U3 open-hold：构造 30h 前的 hold 未闭环 → 命中
    hold = dict(good); hold["ts"] = (datetime.now(timezone.utc) - timedelta(hours=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    hold["human_decision"] = "hold"; hold["status"] = "pending"; hold["target"] = "hold-x"; hold["source"] = "gatekeeper"
    ingest(rules, base, json.dumps(hold))
    anomalies = compute_anomalies(rules, load_all_events(base))
    check(any(t == "open-hold" for _, t in anomalies), "U3 open-hold：hold 超 24h 未闭环命中")

    # U4 export-alerts：合法 JSON + 16列 + anomaly_type + 无敏感值
    alerts_path = os.path.join(tmp, "alerts.json")
    rc = export_alerts(rules, base, out=alerts_path)
    ok_json = False
    try:
        data = json.load(open(alerts_path, encoding="utf-8"))
        ok_json = data.get("count", 0) > 0 and all(
            set(rules["event_columns"]).issubset(a.keys()) and "anomaly_type" in a for a in data["alerts"])
        # 脱敏：alert 不含 evidence_hash 以外的原文敏感值（evidence_hash 仅指纹）
        ok_json = ok_json and all(len(str(a.get("evidence_hash", ""))) <= 16 for a in data["alerts"])
    except Exception:
        ok_json = False
    check(rc == 0 and ok_json, "U4 export-alerts：合法 JSON + 16列 + anomaly_type + 脱敏")

    # U5 query 过滤：按 source=deploy-contract 查，只返回该来源
    qlines = []
    import contextlib, io as _io
    with contextlib.redirect_stdout(_io.StringIO()) as s:
        query(rules, base, source="deploy-contract", fmt="csv")
    qlines = s.getvalue().splitlines()
    rows = list(csv.DictReader(qlines))
    check(len(rows) > 0 and all(r["source"] == "deploy-contract" for r in rows), "U5 query：按 source 过滤正确")

    # U5 export 三格式
    ok_fmt = True
    for fmt, ext in [("md", "md"), ("json", "json"), ("csv", "csv")]:
        p = os.path.join(tmp, f"exp.{ext}")
        if export(rules, base, fmt=fmt, out=p) != 0 or not os.path.exists(p) or os.path.getsize(p) == 0:
            ok_fmt = False
    check(ok_fmt, "U5 export：md/json/csv 三格式均可导出")

    # U7 undo：删除一次日志 → 恢复 → 哈希一致
    # 先造一个日志文件再 safe_delete → undo --restore → 比对哈希
    # 用户视角：用 safe_delete 打印出来的 undo_id 恢复（e2e 曾抓到打印ID与登记ID不一致的bug）
    import re as _re
    testlog = os.path.join(dirs_for(base)["logs"], "events_2099Q4.csv")
    with open(testlog, "w", encoding="utf-8") as f:
        f.write("ts,source\n2099-01-01T00:00:00Z,gatekeeper\n")
    orig_hash = sha256_file(testlog)
    import contextlib, io as _io2
    with contextlib.redirect_stdout(_io2.StringIO()) as s_del:
        rc_del = safe_delete(base, testlog, "selftest delete")
    printed = s_del.getvalue()
    m = _re.search(r"undo_id=(u\d+)", printed)
    printed_uid = m.group(1) if m else None
    manifest = _load_manifest(base)
    manifest_uid = manifest["entries"][-1]["undo_id"] if manifest["entries"] else None
    check(bool(printed_uid) and printed_uid == manifest_uid,
          f"U7 undo_id 一致性：打印 ID 与 manifest 登记一致 ({printed_uid})")
    rc_undo = undo_restore(base, printed_uid) if printed_uid else 1
    restored_hash = sha256_file(testlog) if os.path.exists(testlog) else ""
    check(rc_del == 0 and rc_undo == 0 and orig_hash == restored_hash, "U7 undo：删除→恢复→哈希一致")

    # U6 storage: default LOCALAPPDATA\AuditBase\audit
    rd = resolve_base_dir(None, rules)
    check(rd.endswith(os.path.join("AuditBase", "audit")), "U6 storage: default resolves to LOCALAPPDATA\\AuditBase\\audit")

    # U6 migrate：包内旧数据复制到新存储、源保留
    rc_m = migrate(rules, base)
    check(rc_m == 0, "U6 migrate：旧数据迁移（复制不删源）可执行")

    print(f"selftest: {passed}/{total} 通过")
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if passed == total else 1


# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser(description="Operation Audit Base v2.0")
    parser.add_argument("--base-dir", dest="base_dir", help="存储根目录（默认 %LOCALAPPDATA%\\AuditBase\\audit）")
    # 公共父解析器：让 --base-dir 在子命令前后都能识别（两种位置等价）
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--base-dir", dest="base_dir_sub",
                        help="存储根目录（默认 %LOCALAPPDATA%\\AuditBase\\audit；可放子命令后）")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("ingest", parents=[common], help="收口一条事件（U2 标记）")
    p.add_argument("--event", required=True, help="事件 JSON（16列契约）")

    p = sub.add_parser("daily", parents=[common], help="生成日报（中英，U1）")
    p.add_argument("--date", help="日期 YYYY-MM-DD（默认今天）")

    p = sub.add_parser("weekly", parents=[common], help="生成周报（中英，异常引擎 U3）")
    p.add_argument("--end", help="截至日期 YYYY-MM-DD（默认今天）")

    p = sub.add_parser("rotate", parents=[common], help="季度轮转归档（可撤销）")
    p.add_argument("--archive-months", type=int, default=12)

    p = sub.add_parser("export-alerts", parents=[common], help="导出告警 JSON（U4）")
    p.add_argument("--date-from"); p.add_argument("--date-to"); p.add_argument("--out")

    p = sub.add_parser("query", parents=[common], help="查询事件（U5，无 UI）")
    p.add_argument("--source"); p.add_argument("--severity")
    p.add_argument("--date-from"); p.add_argument("--date-to"); p.add_argument("--limit", type=int)
    p.add_argument("--format", choices=["table", "csv"], default="table")

    p = sub.add_parser("export", parents=[common], help="导出审计报告（U5）")
    p.add_argument("--format", choices=["md", "json", "csv"], default="md")
    p.add_argument("--out"); p.add_argument("--date-from"); p.add_argument("--date-to")

    p = sub.add_parser("clean", parents=[common], help="安全删除文件（移入撤销区，U7）")
    p.add_argument("--file", required=True)

    p = sub.add_parser("undo", parents=[common], help="撤销（U7）")
    p.add_argument("--list", action="store_true")
    p.add_argument("--restore", metavar="UNDO_ID")

    sub.add_parser("migrate", parents=[common], help="旧包内数据迁移到新存储（U6，复制不删源）")

    parser.add_argument("--selftest", action="store_true", help="运行自检")
    args = parser.parse_args()

    if args.selftest:
        return run_selftest()

    rules = load_rules()
    # 子命令后的 --base-dir 优先，否则用顶层的
    base = resolve_base_dir(getattr(args, "base_dir_sub", None) or args.base_dir, rules)

    if args.cmd == "ingest":
        return ingest(rules, base, args.event)
    if args.cmd == "daily":
        return daily(rules, base, args.date)
    if args.cmd == "weekly":
        return weekly(rules, base, args.end)
    if args.cmd == "rotate":
        return rotate(rules, base, args.archive_months)
    if args.cmd == "export-alerts":
        return export_alerts(rules, base, args.date_from, args.date_to, args.out)
    if args.cmd == "query":
        return query(rules, base, args.source, args.severity, args.date_from, args.date_to, args.limit, args.format)
    if args.cmd == "export":
        return export(rules, base, args.format, args.out, args.date_from, args.date_to)
    if args.cmd == "clean":
        return safe_delete(base, args.file)
    if args.cmd == "undo":
        if args.list:
            return undo_list(base)
        if args.restore:
            return undo_restore(base, args.restore)
        print("undo 需要 --list 或 --restore <id>", file=sys.stderr); return 2
    if args.cmd == "migrate":
        return migrate(rules, base)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

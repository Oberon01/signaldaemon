#!/usr/bin/env python3
"""
signaldaemon_export.py
Query and export records from detections.sqlite with flexible filters.

Usage examples:
  python signaldaemon_export.py --db detections.sqlite --since "2h" --match-type match
  python signaldaemon_export.py --db detections.sqlite --since "24h" --min-severity High --out csv --outfile detections.csv
  python signaldaemon_export.py --db detections.sqlite --since "7d" --proc contains:chrome --domain contains:google --out json
  python signaldaemon_export.py --db detections.sqlite --since "1h" --unique domain-proc
"""
import argparse
import datetime as dt
import os
import re
import sqlite3
import sys
import json
import csv
from typing import List, Tuple, Dict, Any, Optional

SEV_ORDER = {"Low": 1, "Medium": 2, "High": 3}

def parse_since(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    s = s.strip()
    now = dt.datetime.now()
    m = re.match(r"^(\d+)([hmd])$", s, re.I)
    if m:
        n = int(m.group(1))
        unit = m.group(2).lower()
        if unit == "m":
            delta = dt.timedelta(minutes=n)
        elif unit == "h":
            delta = dt.timedelta(hours=n)
        elif unit == "d":
            delta = dt.timedelta(days=n)
        else:
            raise ValueError("Unsupported unit")
        return (now - delta).isoformat() + "Z"
    try:
        ts = dt.datetime.fromisoformat(s.replace("Z",""))
        if ts.tzinfo:
            ts = ts.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return ts.isoformat() + "Z"
    except Exception:
        raise ValueError("Invalid --since format. Use '2h', '30m', '1d', or ISO timestamp.")

def parse_filters(args) -> Tuple[str, List[Any]]:
    where = []
    params: List[Any] = []
    if args.since:
        since = parse_since(args.since)
        where.append("ts >= ?")
        params.append(since)
    if args.until:
        until = parse_since(args.until)
        where.append("ts <= ?")
        params.append(until)
    if args.min_severity:
        where.append("""
        CASE severity
            WHEN 'Low' THEN 1
            WHEN 'Medium' THEN 2
            WHEN 'High' THEN 3
            ELSE 0
        END >= ?
        """)
        params.append(SEV_ORDER[args.min_severity])
    if args.match_type:
        where.append("match_type = ?")
        params.append(args.match_type)
    if args.category:
        where.append("category = ?")
        params.append(args.category)
    if args.proc:
        mode, val = args.proc.split(":", 1) if ":" in args.proc else ("eq", args.proc)
        if mode == "contains":
            where.append("LOWER(process_name) LIKE ?")
            params.append(f"%{val.lower()}%")
        else:
            where.append("process_name = ?")
            params.append(val)
    if args.domain:
        mode, val = args.domain.split(":", 1) if ":" in args.domain else ("contains", args.domain)
        if mode == "contains":
            where.append("(LOWER(dest_domain) LIKE ? OR LOWER(matched_domain) LIKE ?)")
            params.extend([f"%{val.lower()}%", f"%{val.lower()}%"])
        else:
            where.append("(dest_domain = ? OR matched_domain = ?)")
            params.extend([val, val])
    if args.ip:
        where.append("(dest_ip = ?)")
        params.append(args.ip)
    where_clause = (" WHERE " + " AND ".join(w.strip() for w in where)) if where else ""
    return where_clause, params

def build_select(args) -> str:
    cols = args.columns.split(",") if args.columns else [
        "ts","process_name","pid","dest_ip","dest_domain","matched_domain","category","severity","match_type","laddr","lport","raddr","rport"
    ]
    select_cols = ", ".join(c.strip() for c in cols)
    base = f"SELECT {select_cols} FROM detections"
    return base

def apply_unique(rows: List[Dict[str,Any]], mode: Optional[str]) -> List[Dict[str,Any]]:
    if not mode:
        return rows
    seen = set()
    out = []
    for r in rows:
        if mode == "remote":
            key = (r.get("dest_ip"),)
        elif mode == "domain":
            key = (r.get("matched_domain") or r.get("dest_domain") or r.get("dest_ip"),)
        elif mode == "remote-proc":
            key = (r.get("process_name"), r.get("dest_ip"))
        elif mode == "domain-proc":
            key = (r.get("process_name"), r.get("matched_domain") or r.get("dest_domain") or r.get("dest_ip"))
        else:
            key = (r.get("pid"), r.get("laddr"), r.get("lport"), r.get("dest_ip"), r.get("rport"))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out

def fetch_rows(db_path: str, sql: str, params: List[Any], order: str, limit: Optional[int]) -> List[Dict[str,Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    order_clause = ""
    if order:
        if order not in ("ts", "severity", "process_name", "dest_domain", "matched_domain", "dest_ip"):
            order = "ts"
        direction = "DESC" if order == "ts" else "ASC"
        order_clause = f" ORDER BY {order} {direction}"
    limit_clause = f" LIMIT {int(limit)}" if limit else ""
    cur.execute(sql + order_clause + limit_clause, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def main():
    ap = argparse.ArgumentParser(description="SignalDaemon detections exporter")
    ap.add_argument("--db", required=True, help="Path to detections.sqlite")
    ap.add_argument("--since", help="Start time (e.g., 2h, 30m, 1d, or ISO8601)")
    ap.add_argument("--until", help="End time")
    ap.add_argument("--min-severity", choices=["Low","Medium","High"], help="Minimum severity to include")
    ap.add_argument("--match-type", choices=["match","baseline"], help="Filter by match_type")
    ap.add_argument("--category", choices=["OS_Telemetry","App_Telemetry","Browser_Tracker","Baseline"], help="Filter by category")
    ap.add_argument("--proc", help="Process filter. e.g., 'contains:chrome' or 'eq:OneDrive.exe'")
    ap.add_argument("--domain", help="Domain filter. e.g., 'contains:google' or 'eq:google-analytics.com'")
    ap.add_argument("--ip", help="Exact destination IP filter")
    ap.add_argument("--columns", help="Comma-separated columns to select")
    ap.add_argument("--order", default="ts", help="Order by column (default ts)")
    ap.add_argument("--limit", type=int, help="Limit number of rows")
    ap.add_argument("--unique", choices=["tuple","remote","domain","remote-proc","domain-proc"], help="Return unique rows by key")
    ap.add_argument("--out", choices=["table","csv","json"], default="table", help="Output format")
    ap.add_argument("--outfile", help="Path for CSV/JSON output")
    args = ap.parse_args()
    if not os.path.exists(args.db):
        print(f"DB not found: {args.db}", file=sys.stderr)
        sys.exit(2)
    where, params = parse_filters(args)
    sql = build_select(args) + where
    rows = fetch_rows(args.db, sql, params, args.order, args.limit)
    if args.unique:
        rows = apply_unique(rows, args.unique)
    if args.out == "json":
        data = json.dumps(rows, indent=2)
        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as f:
                f.write(data)
            print(f"Wrote JSON -> {args.outfile}")
        else:
            print(data)
    elif args.out == "csv":
        if not rows:
            print("No rows.", file=sys.stderr)
            sys.exit(0)
        cols = list(rows[0].keys())
        if args.outfile:
            with open(args.outfile, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=cols)
                w.writeheader()
                w.writerows(rows)
            print(f"Wrote CSV -> {args.outfile} ({len(rows)} rows)")
        else:
            w = csv.DictWriter(sys.stdout, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
    else:
        if not rows:
            print("No rows.")
            sys.exit(0)
        cols = list(rows[0].keys())
        widths = [max(len(str(r.get(c,""))) for r in rows + [{c:c}]) for c in cols]
        fmt = " | ".join("{:<" + str(w) + "}" for w in widths)
        print(fmt.format(*cols))
        print("-+-".join("-"*w for w in widths))
        for r in rows:
            print(fmt.format(*[str(r.get(c,"")) for c in cols]))

if __name__ == "__main__":
    main()

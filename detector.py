import argparse
import datetime as dt
import socket
import sqlite3
import time
import psutil
import ipaddress
from typing import Optional, List, Tuple, Set
import os
from datetime import datetime

from blocklist_loader import Blocklist
from notifier import notify

# notification cache (dest_domain/process -> last_time)
_notify_cache = {}

# ---------- helpers ----------

def is_private_ip(ip: str) -> bool:
    try:
        ipobj = ipaddress.ip_address(ip)
        return ipobj.is_private or ipobj.is_loopback or ipobj.is_link_local
    except ValueError:
        return False

def reverse_dns(ip: str, timeout: float = 0.25) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""

def ensure_detections_db(path: str):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        process_name TEXT,
        pid INTEGER,
        laddr TEXT,
        lport INTEGER,
        raddr TEXT,
        rport INTEGER,
        dest_ip TEXT,
        dest_domain TEXT,
        matched_domain TEXT,
        category TEXT,
        severity TEXT,
        match_type TEXT DEFAULT 'match' -- 'match' or 'baseline'
    );
    """)
    # migrate older DBs that lack match_type
    try:
        cur.execute("SELECT match_type FROM detections LIMIT 1")
    except sqlite3.OperationalError:
        cur.execute("ALTER TABLE detections ADD COLUMN match_type TEXT DEFAULT 'match'")
    conn.commit()
    conn.close()

def log_detection(path: str, row: dict):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO detections (ts, process_name, pid, laddr, lport, raddr, rport,
                            dest_ip, dest_domain, matched_domain, category, severity, match_type)
    VALUES (:ts, :process_name, :pid, :laddr, :lport, :raddr, :rport,
            :dest_ip, :dest_domain, :matched_domain, :category, :severity, :match_type)
    """, row)
    conn.commit()
    conn.close()

def gather_conns(only_established: bool) -> List[psutil._common.sconn]:
    conns = psutil.net_connections(kind="inet")
    if only_established:
        conns = [c for c in conns if getattr(c, "status", "") == psutil.CONN_ESTABLISHED]
    return [c for c in conns if c.raddr]

def _ensure_dir(p: str):
    d = os.path.dirname(os.path.abspath(p))
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def _write_log_line(log_path: str, line: str):
    _ensure_dir(log_path)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def log_match_line(log_path: str, severity: str, process: str, pid: int,
                   host: str, category: str, tag: str = ""):
    # Local timestamp for human readability
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    proc = process or "process"
    h = host or "no-host"
    suffix = f" [{tag}]" if tag else ""
    line = f"[{ts}] [{severity.upper()}] {proc} (pid {pid}) -> {h} [{category}]{suffix}"
    _write_log_line(log_path, line)

# ---------- core scan ----------

def scan_once(
    bl: Blocklist,
    detections_db: str,
    severity_threshold: str = "High",
    verbose: bool = True,
    only_established: bool = True,
    debug: bool = False,
    log_all: bool = False,
    external_only: bool = True,
    baseline_seen: Optional[Set[Tuple[int, str, int, str, int]]] = None,
    dedupe_baseline: bool = False,
    do_notify: bool = False,
    notify_min: str = "Low",
    notify_squelch: float = 60.0,
    match_log: str | None = None,
    log_baselines: bool = False
) -> Tuple[int, int]:
    """
    Returns (match_count, baseline_count).
    """
    sev_order = {"Low": 1, "Medium": 2, "High": 3}
    threshold = sev_order.get(severity_threshold, 3)

    ensure_detections_db(detections_db)

    matches = 0
    baselines = 0
    conns = gather_conns(only_established)
    rdns_hits = 0
    debug_samples = []

    for c in conns:
        dest_ip = c.raddr.ip
        if external_only and is_private_ip(dest_ip):
            continue

        dest_domain = reverse_dns(dest_ip)
        if dest_domain:
            rdns_hits += 1
        pid = c.pid or 0
        try:
            pname = psutil.Process(pid).name() if pid else ""
        except Exception:
            pname = ""

        matched = None
        if dest_domain:
            matched = bl.match_domain(dest_domain)
        if not matched:
            matched = bl.match_ip(dest_ip)

        ts_now = dt.datetime.now().isoformat() + "Z"
        laddr_ip = getattr(c.laddr, "ip", "")
        laddr_port = getattr(c.laddr, "port", 0)
        raddr_ip = getattr(c.raddr, "ip", "")
        raddr_port = getattr(c.raddr, "port", 0)

        if matched:
            m_domain, m_cat, m_sev = matched

            # Notifications (rate-limited)
            if do_notify:
                if sev_order.get(m_sev, 1) >= sev_order.get(notify_min, 3):
                    key = (pname, m_domain or dest_domain or dest_ip)
                    now_ts = time.time()
                    last = _notify_cache.get(key, 0)
                    if now_ts - last >= notify_squelch:
                        title = f"SignalDaemon: {m_sev} {m_cat}"
                        body = f"{pname or 'process'} → {m_domain or dest_domain or dest_ip}"
                        notify(title, body)
                        _notify_cache[key] = now_ts

            row = {
                "ts": ts_now,
                "process_name": pname,
                "pid": pid,
                "laddr": laddr_ip,
                "lport": laddr_port,
                "raddr": raddr_ip,
                "rport": raddr_port,
                "dest_ip": dest_ip,
                "dest_domain": dest_domain,
                "matched_domain": m_domain,
                "category": m_cat,
                "severity": m_sev,
                "match_type": "match",
            }
            if sev_order.get(m_sev, 1) >= threshold:
                log_detection(detections_db, row)
                matches += 1
                if verbose:
                    print(f"[MATCH] {pname} (pid {pid}) -> {dest_ip} ({dest_domain or 'no-rdns'}) :: {m_domain} [{m_cat}/{m_sev}]")
        
                if match_log:
                    host_for_log = m_domain or dest_domain or dest_ip
                    log_match_line(match_log, m_sev, pname, pid, host_for_log, m_cat)
        else:
            if log_all:
                key = (pid, laddr_ip, laddr_port, raddr_ip, raddr_port)
                if dedupe_baseline and baseline_seen is not None:
                    if key in baseline_seen:
                        continue
                    baseline_seen.add(key)
                row = {
                    "ts": ts_now,
                    "process_name": pname,
                    "pid": pid,
                    "laddr": laddr_ip,
                    "lport": laddr_port,
                    "raddr": raddr_ip,
                    "rport": raddr_port,
                    "dest_ip": dest_ip,
                    "dest_domain": dest_domain,
                    "matched_domain": "",
                    "category": "Baseline",
                    "severity": "Low",
                    "match_type": "baseline",
                }
                log_detection(detections_db, row)
                baselines += 1
                if match_log and log_baselines:
                    host_for_log = dest_domain or dest_ip
                    log_match_line(match_log, "Low", pname, pid, host_for_log, "Baseline", tag="BASELINE")

                if verbose and debug:
                    print(f"[BASE]  {pname} (pid {pid}) -> {dest_ip} ({dest_domain or 'no-rdns'})")
            elif debug and len(debug_samples) < 15:
                debug_samples.append((pname, pid, dest_ip, dest_domain))

    if verbose:
        total = len(conns)
        print(f"[SCAN] Conns scanned: {total} | rDNS resolved: {rdns_hits} | Matches >= {severity_threshold}: {matches} | Baseline logged: {baselines}")
        if debug and debug_samples and not log_all:
            print("[DEBUG] Sample of unmatched connections:")
            for pname, pid, ip, dom in debug_samples:
                print(f"  - {pname or 'unknown'} (pid {pid}) -> {ip} ({dom or 'no-rdns'})")

    return matches, baselines

# ---------- watch (daemon-ish) ----------

def watch(
    blocklist_db: str,
    detections_db: str,
    threshold: str,
    interval: float,
    verbose: bool,
    only_established: bool,
    debug: bool,
    log_all: bool,
    external_only: bool,
    dedupe_baseline: bool,
    duration: Optional[float],
    do_notify: bool,
    notify_min: str,
    notify_squelch: float,
    match_log: str | None = None,
    log_baselines: bool = False
):
    bl = Blocklist()
    bl.load_from_sqlite(blocklist_db)
    bl.pre_resolve_dns(limit=600)

    ensure_detections_db(detections_db)

    baseline_seen: Set[Tuple[int, str, int, str, int]] = set() if dedupe_baseline else None

    print(f"[WATCH] SignalDaemon running. Interval={interval}s, Threshold={threshold}, "
          f"EstablishedOnly={only_established}, LogAll={log_all}, ExternalOnly={external_only}, "
          f"DedupeBaseline={dedupe_baseline}, Duration={duration or '∞'}, Notify={do_notify}, NotifyMin={notify_min}")

    start_time = time.time()
    try:
        while True:
            scan_once(
                bl, detections_db, threshold, verbose=verbose,
                only_established=only_established, debug=debug,
                log_all=log_all, external_only=external_only,
                baseline_seen=baseline_seen, dedupe_baseline=dedupe_baseline,
                do_notify=do_notify, notify_min=notify_min, notify_squelch=notify_squelch,
                match_log=match_log, log_baselines=log_baselines
            )
            if duration is not None and (time.time() - start_time) >= duration:
                print("[WATCH] Duration reached. Exiting.")
                break
            if verbose:
                print(f"[IDLE] Sleeping {interval:.2f}s ...")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[WATCH] Stopped by user.")

# ---------- cli ----------

def main():
    ap = argparse.ArgumentParser(description="SignalDaemon MVP")
    ap.add_argument("--blocklist-db", required=True, help="Path to signaldaemon_blocklist.sqlite")
    ap.add_argument("--detections-db", default="detections.sqlite", help="Where to store detections")
    ap.add_argument("--threshold", choices=["Low", "Medium", "High"], default="High", help="Severity threshold to log")

    ap.add_argument("--watch", action="store_true", help="Run continuously (daemon-like)")
    ap.add_argument("--interval", type=float, default=10.0, help="Seconds between scans in --watch mode")
    ap.add_argument("--duration", type=float, default=None, help="Stop after N seconds in --watch mode")

    ap.add_argument("--quiet", action="store_true", help="Reduce console output")
    ap.add_argument("--all-states", action="store_true", help="Include non-ESTABLISHED connections")
    ap.add_argument("--debug", action="store_true", help="Print unmatched sample and scan stats")

    ap.add_argument("--log-all", action="store_true", help="Log all *external* connections as baseline when not matched")
    ap.add_argument("--include-internal", action="store_true", help="Also log internal/private IPs when using --log-all")
    ap.add_argument("--dedupe-baseline", action="store_true", help="Only log the first time a unique baseline connection is seen per session")

    ap.add_argument("--notify", action="store_true", help="Show a local notification when a match occurs")
    ap.add_argument("--notify-min-severity", choices=["Low","Medium","High"], default="High", help="Minimum severity to trigger notifications")
    ap.add_argument("--notify-squelch", type=float, default=60.0, help="Seconds to suppress duplicate notifications for the same destination/process")

    ap.add_argument("--match-log", default="matches.log", help="Plain-text log file for detections (set to '' to disable)")
    ap.add_argument("--log-baselines", action="store_true", help="Also write baseline (non-match) entries to the plain-text log")

    args = ap.parse_args()

    verbose = not args.quiet
    only_established = not args.all_states
    log_all = args.log_all
    external_only = not args.include_internal

    if args.watch:
        watch(
            args.blocklist_db, args.detections_db, args.threshold, args.interval,
            verbose, only_established, args.debug, log_all, external_only,
            args.dedupe_baseline, args.duration,
            args.notify, args.notify_min_severity, args.notify_squelch,
            match_log=args.match_log if args.match_log else None,
            log_baselines=args.log_baselines
        )
    else:
        bl = Blocklist()
        bl.load_from_sqlite(args.blocklist_db)
        bl.pre_resolve_dns(limit=600)
        scan_once(
            bl, args.detections_db, args.threshold, verbose=verbose,
            only_established=only_established, debug=args.debug,
            log_all=log_all, external_only=external_only,
            do_notify=args.notify, notify_min=args.notify_min_severity, notify_squelch=args.notify_squelch, match_log=(args.match_log if args.match_log else None), log_baselines=args.log_baselines
        )

if __name__ == "__main__":
    main()

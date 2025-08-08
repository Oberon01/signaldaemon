
import sqlite3
import socket
import time
from typing import Dict, List, Optional, Set, Tuple

class BlocklistEntry:
    __slots__ = ("domain", "ip_address", "category", "severity", "source")
    def __init__(self, domain: str, ip_address: Optional[str], category: str, severity: str, source: Optional[str]):
        self.domain = domain.lower().strip()
        self.ip_address = (ip_address or "").strip()
        self.category = category
        self.severity = severity
        self.source = source or ""

class Blocklist:
    """
    Loads blocklist from SQLite/CSV/JSON and provides fast IP/domain matching.
    - Domain matching is exact or suffix-match (e.g., *.example.com)
    - IP matching is exact (optional; most entries are domain-based)
    - DNS pre-resolution caches A records for domains to speed IP matching
    """
    def __init__(self):
        self._domains: Set[str] = set()
        self._domain_suffixes: Set[str] = set()  # like ".doubleclick.net"
        self._ips: Set[str] = set()
        self._meta: Dict[str, Tuple[str, str]] = {}  # domain -> (category, severity)
        self._dnscache: Dict[str, Tuple[float, Set[str]]] = {}  # domain -> (ts, {ip,...})
        self.dns_ttl_sec = 3600

    def load_from_sqlite(self, path: str, table: str = "blocklist") -> int:
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute(f"SELECT domain, ip_address, category, severity FROM {table}")
        rows = cur.fetchall()
        conn.close()
        return self._ingest_rows(rows)

    def load_from_json(self, path: str) -> int:
        import json
        with open(path, "r") as f:
            data = json.load(f)
        rows = [(d["domain"], d.get("ip_address"), d["category"], d["severity"]) for d in data]
        return self._ingest_rows(rows)

    def load_from_csv(self, path: str) -> int:
        import csv
        rows = []
        with open(path, newline="") as f:
            r = csv.DictReader(f)
            for row in r:
                rows.append((row["domain"], row.get("ip_address"), row["category"], row["severity"]))
        return self._ingest_rows(rows)

    def _ingest_rows(self, rows: List[Tuple[str, Optional[str], str, str]]) -> int:
        count = 0
        for domain, ip, category, severity in rows:
            if domain:
                d = domain.lower().strip()
                self._domains.add(d)
                # suffix form for fast endswith checks
                if not d.startswith("."):
                    self._domain_suffixes.add("." + d)
                else:
                    self._domain_suffixes.add(d)
                self._meta[d] = (category, severity)
                count += 1
            if ip:
                self._ips.add(ip.strip())
        return count

    def _dns_lookup(self, domain: str) -> Set[str]:
        now = time.time()
        cached = self._dnscache.get(domain)
        if cached and now - cached[0] < self.dns_ttl_sec:
            return cached[1]
        ips: Set[str] = set()
        try:
            # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
            res = socket.gethostbyname_ex(domain)
            for ip in res[2]:
                ips.add(ip)
        except Exception:
            pass
        self._dnscache[domain] = (now, ips)
        return ips

    def pre_resolve_dns(self, limit: Optional[int] = 200) -> int:
        n = 0
        for d in list(self._domains):
            if limit and n >= limit:
                break
            self._dns_lookup(d)
            n += 1
        return n

    def match_ip(self, ip: str) -> Optional[Tuple[str, str, str]]:
        """Return (matched_domain_or_ip, category, severity) if ip matches via exact IP or DNS-resolved domain set."""
        if ip in self._ips:
            # pick a generic tag if we stored IP directly (rare)
            return (ip, "Unknown", "Medium")
        # Try mapping to any domain we know (reverse via A-record forward map)
        for d, (category, severity) in self._meta.items():
            ips = self._dnscache.get(d, (0, set()))[1] or self._dns_lookup(d)
            if ip in ips:
                return (d, category, severity)
        return None

    def match_domain(self, domain: str) -> Optional[Tuple[str, str, str]]:
        if not domain:
            return None
        d = domain.lower().strip()
        if d in self._domains:
            cat, sev = self._meta.get(d, ("Unknown", "Low"))
            return (d, cat, sev)
        # suffix: "sub.example.com" endswith ".example.com"
        for s in self._domain_suffixes:
            if d.endswith(s):
                base = s[1:]
                cat, sev = self._meta.get(base, ("Unknown", "Low"))
                return (base, cat, sev)
        return None


# SignalDaemon MVP — Detection Pass (Prototype)

This prototype gives you two things:
1) A **BlocklistLoader** that reads the SQLite blocklist and provides fast domain/IP matching (with DNS caching).
2) A **single-pass detector** that maps active connections to processes and logs matches with severity filtering.

## Files
- `blocklist_loader.py` — loads domains/IPs from `signaldaemon_blocklist.sqlite`, caches DNS, and exposes `match_ip` / `match_domain`.
- `detector.py` — runs a one-time scan using `psutil`, attempts rDNS, and logs detections to `detections.sqlite`.
- `requirements.txt` — minimal dependency list.

## Quick Start
1. Ensure you have Python 3.10+ and install deps:
   ```bash
   pip install -r requirements.txt
   SignalDaemon — detection and logging daemon

   SignalDaemon monitors active network connections on a host, matches destinations
   against a curated blocklist (domains/IPs), and records matches to a SQLite
   database and a plain-text log. It can optionally show desktop notifications
   for higher-severity events.

   This repository contains a refactored package layout under `src/signaldaemon/`
   and a small CLI wrapper. Key modules:

   - `src/signaldaemon/blocklist.py` — blocklist loader and DNS caching
   - `src/signaldaemon/scanner.py` — connection scanning and matching logic
   - `src/signaldaemon/notifier.py` — desktop notification helpers (Windows fallback)
   - `src/signaldaemon/exporter.py` — query/export utilities for `detections.sqlite`
   - `src/signaldaemon/cli.py` — command-line entrypoint (console script `signaldaemon`)

   Quick start

   1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

   2. Edit configuration if desired: `config/defaults.toml` or create `config/config.toml`.

   3. Run a single scan (uses config.defaults if you omit args):

   ```bash
   python -m signaldaemon.cli --blocklist-db ../signaldaemon_blocklist/signaldaemon_blocklist.sqlite
   ```

   4. To run continuously (watch mode):

   ```bash
   python -m signaldaemon.cli --blocklist-db ../signaldaemon_blocklist/signaldaemon_blocklist.sqlite --watch
   ```

   Configuration

   Defaults are in `config/defaults.toml`. You can override values by creating
   `config/config.toml` in the project root, or by setting environment variables
   prefixed with `SIGNALDAEMON_` (for example `SIGNALDAEMON_NOTIFY=false`).

   Examples

   - Export recent high-severity matches to CSV:

   ```bash
   python src/signaldaemon/signaldaemon_export.py --db data/detections.sqlite --since 24h --min-severity High --out csv --outfile recent.csv
   ```

   Notes & next steps

   - The scanner performs best-effort reverse DNS lookups; lack of rDNS does not
     prevent IP-based matching.
   - This project currently detects and logs only; it does not block traffic.
   - Planned improvements: service/daemon wrappers, automatic blocklist updates,
     web or GUI for browsing `detections.sqlite`, and unit tests.

   If you want, I can: wire an installer/packaging flow, add a systemd service
   example, or add unit tests for the blocklist and exporter modules.

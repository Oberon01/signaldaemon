
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
   ```
2. Run a single detection pass (will log only High severity by default):
   ```bash
   python detector.py --blocklist-db ../signaldaemon_blocklist/signaldaemon_blocklist.sqlite --detections-db detections.sqlite --threshold High
   ```

## Notes
- **rDNS is best-effort** and may be empty; IP matching still works via DNS-forward cache of blocklist domains.
- For MVP we **detect only**. Do not block yet.
- Next steps: daemonize, add notifications, and build a tiny UI table for `detections.sqlite`.

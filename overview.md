**SignalDaemon: High-Level Overview**

---

**Purpose**
SignalDaemon is a daemonized monitoring tool designed to detect, log, and alert on network activity that may indicate telemetry, surveillance, or unwanted data collection at the OS, browser, and network levels.

Its design philosophy is guided by the Threshold Sovereign Execution Protocol — focusing on autonomy, low maintenance, high leverage, and asymmetrical advantage.

---

**Core Functions**

1. **Real-Time Process & Connection Monitoring**

   * Observes active network connections from running processes.
   * Captures process name, PID, destination IP, reverse DNS, and matched category.

2. **Blocklist Matching**

   * Compares observed connections against a curated SQLite blocklist database.
   * Each match is classified by category (e.g., OS Telemetry, Ad Tracking) and severity (Low/Medium/High).

3. **Event Logging**

   * Structured logging into `detections.sqlite` for detailed historical analysis.
   * Append-only plain-text `matches.log` for quick human-readable review.
   * Optional baseline logging for known, non-critical connections.

4. **Notifications**

   * Local, real-time Windows notifications when a match meets or exceeds severity threshold.
   * Configurable minimum severity and squelch timer to avoid spam.

5. **Daemonized Operation**

   * Runs continuously at set intervals (seconds) without user intervention.
   * Minimal CPU/memory footprint for 24/7 monitoring.

---

**MVP Feature Set (Current)**

* SQLite blocklist + detection DB.
* Real-time scanning loop.
* Console match display.
* Notification pop-ups for matches.
* Human-readable match logging.
* Configurable thresholds and notification behavior.
* Optional baseline logging.

---

**Planned Near-Term Additions**

* Config file for default parameters (Step 3).
* Blocklist updater daemon.
* Severity-based notification styles.
* Remote webhook integration for sending match data to other systems.
* Minimal GUI for non-CLI users.

---

**Strategic Design Goals**

* **Autonomy:** Operates without manual babysitting.
* **High Leverage:** Each feature is designed to provide maximum situational awareness with minimal noise.
* **Low Maintenance:** Self-contained with minimal dependencies.
* **Resilience:** Structured logging ensures nothing is lost, even if notifications fail.
* **Selective Engagement:** Surfaces only relevant or high-impact events, avoiding information overload.

---

**Example Workflow**

1. SignalDaemon starts with `--watch` and blocklist.
2. Every scan interval, it checks all active TCP connections.
3. Matches above threshold are:

   * Written to SQLite DB.
   * Written to `matches.log`.
   * Sent to desktop notification.
4. User reviews live console, tails log, or queries DB as needed.

---

**Positioning**
SignalDaemon is not just a network sniffer — it is a focused sovereignty tool, revealing background activity that most systems hide. Its emphasis on minimal user effort and high-value visibility makes it a defensive intelligence asset for privacy-conscious operators.
# Simple-IDS-Monitor

A hybrid **Intrusion Detection System (IDS)** combining Host-based (HIDS) and Network-based (NIDS) detection, with a real-time Flutter dashboard for live alert monitoring.

---

## What It Does

Simple-IDS-Monitor runs multiple detection modules in parallel and streams structured alerts to a live GUI dashboard over UDP/TCP. It detects:

- **File tampering** — monitors a target file for unauthorized modifications
- **Failed login attempts** — tails system logs for SSH/auth failures in real time
- **Suspicious processes** — flags known recon tools like `nmap` if they appear in the process list
- **Port scans** — sniffs network packets and alerts when a single IP probes too many ports

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              Python Backend                 │
│                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  File    │  │   Log    │  │ Process  │  │  ← HIDS (hids.py)
│  │ Monitor  │  │ Monitor  │  │ Monitor  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │             │              │        │
│  ┌────▼─────────────▼──────────────▼─────┐  │
│  │         UDP Alert Sender              │  │
│  │    JSON payload → 127.0.0.1:5005      │  │
│  └───────────────────────────────────────┘  │
│                                             │
│  ┌───────────────────────────────────────┐  │
│  │   Packet Sniffer (nids.py / Scapy)    │  │  ← NIDS
│  │   Port Scan Detection (threshold=10)  │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
                      │ UDP/TCP :5005
┌─────────────────────▼───────────────────────┐
│         Flutter Dashboard (main.dart)        │
│   Real-time alert feed  •  Severity colors   │
└─────────────────────────────────────────────┘
```

---

## Project Structure

```
Simple-IDS-monitor/
├── backend/
│   ├── main.py          # Entry point — starts all threads
│   ├── hids.py          # File, log & process monitoring + UDP alert sender
│   ├── nids.py          # Packet sniffing & port scan detection
│   ├── utils.py         # Alert logger, stats tracker, summary printer
│   ├── important.txt    # Sample monitored file
│   └── logs.txt         # Alert log output
└── frontend/
    └── lib/
        └── main.dart    # Flutter dashboard — TCP/UDP listener + alert UI
```

---

## Prerequisites

**Backend**
- Python 3.x
- Linux (uses `journalctl` for log monitoring; Arch-compatible)
- Root/sudo privileges (required for packet sniffing with Scapy)

Install dependencies:
```bash
pip install scapy psutil zxcvbn
```

**Frontend**
- Flutter SDK (3.x+)
- Dart SDK ^3.11.4

---

## How to Run

### 1. Start the Backend

```bash
cd Simple-IDS-monitor/backend
sudo python main.py
```

> `sudo` is required for Scapy to capture raw packets.

You should see:
```
Starting Hybrid IDS System...

🌐 NIDS Started...
📄 Monitoring system logs (journalctl)...
⚙️ Monitoring processes...
💻 HIDS Started... Monitoring: important.txt
```

### 2. Start the Flutter Dashboard

In a separate terminal:
```bash
cd Simple-IDS-monitor/frontend
flutter run -d linux
```

The dashboard binds to port 5005 on both TCP and UDP and displays incoming alerts in real time.

---

## Detection Modules

### File Integrity Monitor
Watches a target file (`important.txt` by default) using `os.path.getmtime()`. Triggers a `FILE_MODIFIED` alert whenever the file's modification timestamp changes.

```python
# Change the monitored file in main.py
file_to_monitor = "important.txt"
```

### Log Monitor
Tails live system logs via `journalctl -f` and scans for:
- `"Failed password"` — SSH brute-force attempts
- `"authentication failure"` — PAM/auth failures

### Process Monitor
Polls running processes every 200ms using `psutil`. Flags `nmap` (network scanner) as a suspicious process and fires a `SUSPICIOUS_PROCESS` alert with the PID and command line.

### Port Scan Detector
Sniffs TCP packets using Scapy and tracks how many distinct ports each source IP has touched. Triggers a `PORT_SCAN` alert when a single IP exceeds 10 unique ports, with a 10-second cooldown to prevent alert flooding.

---

## Alert Format

All alerts are JSON-encoded and sent over UDP to `127.0.0.1:5005`:

```json
{
  "timestamp": "2025-05-29T14:32:01.123456",
  "event": "FILE_MODIFIED",
  "severity": "medium",
  "message": "File modified: important.txt",
  "file_path": "important.txt"
}
```

| Field | Values |
|---|---|
| `event` | `FILE_MODIFIED`, `FAILED_LOGIN`, `SUSPICIOUS_PROCESS` |
| `severity` | `low`, `medium`, `high`, `critical` |

---

## Dashboard

The Flutter dashboard (`main.dart`) listens on port 5005 over both TCP and UDP. Alerts appear in real time with severity-based color coding:

| Severity | Color |
|---|---|
| High / Critical | 🔴 Red |
| Medium | 🟠 Orange |
| Low | 🔵 Blue |

A green/red dot in the top-right corner indicates whether the listener is active.

---

## Stopping the IDS

Press `Ctrl+C` in the backend terminal. A summary is printed on exit:

```
==================================================
📊 IDS SUMMARY
==================================================
Total Alerts     : 12
NIDS Alerts      : 8
HIDS Alerts      : 4
--------------------------------------------------
Port Scans       : 8
Failed Logins    : 2
File Changes     : 1
Suspicious Procs : 1
==================================================
```

---

## Security Concepts Demonstrated

| Concept | Implementation |
|---|---|
| Host-based IDS (HIDS) | File, log & process monitoring |
| Network-based IDS (NIDS) | Scapy packet sniffing |
| File Integrity Monitoring | `os.path.getmtime()` polling |
| Syslog analysis | `journalctl -f` + pattern matching |
| Port scan detection | Threshold-based per-IP port counting |
| Alert deduplication | Per-IP cooldown timer |
| Structured alerting | UDP JSON payloads |
| Real-time dashboard | Flutter TCP/UDP socket listener |
| Multi-threaded agent | `threading.Thread` per module |

---

## Limitations & Future Improvements

- Port scan detection currently sniffs only the `lo` (loopback) interface — change `iface="lo"` in `nids.py` to monitor an external interface (e.g. `eth0`, `wlan0`)
- NIDS alert currently logs via `utils.alert()` rather than UDP — unifying both to the same sender would simplify the architecture
- Process monitoring only checks for `nmap` — the suspicious process list can be expanded
- No persistent storage; alerts are held in memory and written to `logs.txt`

---

*Built as a cybersecurity learning project demonstrating real-world IDS architecture.*

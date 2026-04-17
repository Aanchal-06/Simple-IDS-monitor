import os
import time
import json
import socket
import psutil
import subprocess
from datetime import datetime


# ─── Config ──────────────────────────────────────────────────────────────────

ALERT_IP   = "127.0.0.1"
ALERT_PORT = 5005


# ─── UDP Alert Sender ─────────────────────────────────────────────────────────

def send_alert(event: str, message: str, severity: str = "high", **extra):
    payload = {
        "timestamp":  datetime.now().isoformat(),
        "event":      event,
        "severity":   severity,
        "message":    message,
        **extra
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(json.dumps(payload).encode("utf-8"), (ALERT_IP, ALERT_PORT))
    except Exception as e:
        print(f"Failed to send alert: {e}")


# ─── File Monitoring ──────────────────────────────────────────────────────────

def monitor_file(file_path):
    print("💻 HIDS Started... Monitoring:", file_path)

    if not os.path.exists(file_path):
        print("File not found!")
        return

    last_modified = os.path.getmtime(file_path)

    while True:
        current_modified = os.path.getmtime(file_path)

        if current_modified != last_modified:
            send_alert(
                event     = "FILE_MODIFIED",
                message   = f"File modified: {file_path}",
                severity  = "medium",
                file_path = file_path
            )
            last_modified = current_modified

        time.sleep(2)


# ─── Log Monitoring (Arch-compatible) ────────────────────────────────────────

def monitor_logs():
    print("📄 Monitoring system logs (journalctl)...")

    try:
        process = subprocess.Popen(
            ["journalctl", "-f"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        while True:
            line = process.stdout.readline()

            if not line:
                continue

            if "Failed password" in line or "authentication failure" in line:
                send_alert(
                    event    = "FAILED_LOGIN",
                    message  = "Failed login attempt detected in system logs",
                    severity = "high",
                    log_line = line.strip()
                )

    except Exception as e:
        print("❌ Log monitoring error:", e)


# ─── Process Monitoring ───────────────────────────────────────────────────────

def monitor_processes():
    print("⚙️ Monitoring processes...")

    seen = set()

    while True:
        current_pids = set()

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pid  = proc.info['pid']
                name = proc.info['name']
                cmd  = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""

                current_pids.add(pid)

                if "nmap" in name or "nmap" in cmd:
                    if pid not in seen:
                        send_alert(
                            event        = "SUSPICIOUS_PROCESS",
                            message      = f"Suspicious process detected: {name}",
                            severity     = "high",
                            process_name = name,
                            pid          = pid,
                            cmdline      = cmd
                        )
                        seen.add(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        seen = seen.intersection(current_pids)
        time.sleep(0.2)
import os
import time
import psutil
import subprocess
from utils import alert


# File Monitoring
def monitor_file(file_path):
    print("💻 HIDS Started... Monitoring:", file_path)

    if not os.path.exists(file_path):
        print("File not found!")
        return

    last_modified = os.path.getmtime(file_path)

    while True:
        current_modified = os.path.getmtime(file_path)

        if current_modified != last_modified:
            alert(f"[HIDS] File modified: {file_path}")
            last_modified = current_modified

        time.sleep(2)


# Log Monitoring (Arch-compatible)
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
                alert("[HIDS] Failed login attempt detected!")

    except Exception as e:
        print("❌ Log monitoring error:", e)


# Process Monitoring
def monitor_processes():
    print("⚙️ Monitoring processes...")

    seen = set()

    while True:
        current_pids = set()

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                cmd = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""

                current_pids.add(pid)

                if "nmap" in name or "nmap" in cmd:
                    if pid not in seen:
                        alert(f"[HIDS] Suspicious process detected: {name}")
                        seen.add(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        #Clean old PIDs (important)
        seen = seen.intersection(current_pids)

        time.sleep(0.2)
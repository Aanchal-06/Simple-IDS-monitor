import os
import time
import psutil
import subprocess
from utils import alert


# 🔹 File Monitoring
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


# 🔹 Log Monitoring (Arch-compatible)
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


# 🔹 Process Monitoring
def monitor_processes():
    print("⚙️ Monitoring processes...")

    while True:
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                name = proc.info['name']
                cmd = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""

                if "nmap" in name or "nmap" in cmd:
                    alert(f"[HIDS] Suspicious process detected: {name}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(1)   # faster detection
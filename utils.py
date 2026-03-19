import datetime

# Stats tracker
stats = {
    "total": 0,
    "nids": 0,
    "hids": 0,
    "port_scan": 0,
    "failed_login": 0,
    "file_change": 0,
    "process": 0
}


def alert(message):
    time = datetime.datetime.now()
    formatted = f"{time} - {message}"

    print("\n" + "="*50)
    print("🚨 ALERT:", formatted)
    print("="*50 + "\n")

    with open("logs.txt", "a") as f:
        f.write(formatted + "\n")

    # Update stats
    stats["total"] += 1

    if "[NIDS]" in message:
        stats["nids"] += 1
        stats["port_scan"] += 1

    if "[HIDS]" in message:
        stats["hids"] += 1

    if "File modified" in message:
        stats["file_change"] += 1

    if "Failed login" in message:
        stats["failed_login"] += 1

    if "Suspicious process" in message:
        stats["process"] += 1


def print_summary():
    print("\n" + "="*50)
    print("📊 IDS SUMMARY")
    print("="*50)

    print(f"Total Alerts: {stats['total']}")
    print(f"NIDS Alerts: {stats['nids']}")
    print(f"HIDS Alerts: {stats['hids']}")
    print("-" * 50)
    print(f"Port Scans: {stats['port_scan']}")
    print(f"Failed Logins: {stats['failed_login']}")
    print(f"File Changes: {stats['file_change']}")
    print(f"Suspicious Processes: {stats['process']}")

    print("="*50 + "\n")
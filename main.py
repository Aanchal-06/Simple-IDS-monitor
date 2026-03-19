import threading
from nids import start_nids
from utils import print_summary
from hids import monitor_file, monitor_logs, monitor_processes

file_to_monitor = "important.txt"

def main():
    print("Starting Hybrid IDS System...\n")

    try:
        # Start NIDS
        threading.Thread(target=start_nids, daemon=True).start()

        # Start HIDS modules
        threading.Thread(target=monitor_logs, daemon=True).start()
        threading.Thread(target=monitor_processes, daemon=True).start()

        # Run file monitoring in main thread
        monitor_file(file_to_monitor)

    except KeyboardInterrupt:
        print("\n🛑 Stopping IDS...")
        print_summary()


if __name__ == "__main__":
    main()
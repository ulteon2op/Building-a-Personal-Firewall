import psutil
import time
import os
from datetime import datetime

# ----------------------------
# Personal Firewall (Simulation)
# ----------------------------

BLOCKED_IPS = {
    "8.8.8.8",
    "1.1.1.1"
}

LOG_FILE = "firewall_log.txt"

seen = set()

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def clear():
    os.system("cls" if os.name == "nt" else "clear")

while True:
    clear()
    print("=" * 90)
    print("          PERSONAL FIREWALL MONITOR")
    print("=" * 90)
    print(f"{'Process':20} {'Local Address':25} {'Remote Address':25} Status")
    print("-" * 90)

    try:
        connections = psutil.net_connections(kind='inet')

        for conn in connections:
            if conn.raddr:

                pid = conn.pid

                try:
                    pname = psutil.Process(pid).name()
                except:
                    pname = "Unknown"

                lip = f"{conn.laddr.ip}:{conn.laddr.port}"
                rip = f"{conn.raddr.ip}:{conn.raddr.port}"

                status = "ALLOWED"

                if conn.raddr.ip in BLOCKED_IPS:
                    status = "BLOCKED"

                print(f"{pname[:18]:20} {lip:25} {rip:25} {status}")

                key = (pname, lip, rip, status)

                if key not in seen:
                    seen.add(key)
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    message = f"[{now}] {status} | {pname} | {lip} -> {rip}"
                    log(message)

    except Exception as e:
        print(e)

    print("\nBlocked IPs:", BLOCKED_IPS)
    print("Logs saved in firewall_log.txt")

    time.sleep(3)
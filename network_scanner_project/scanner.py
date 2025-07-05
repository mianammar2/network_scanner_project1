import argparse
import csv
import json
import socket
import threading
from datetime import datetime
from queue import Queue

from scapy.all import ARP, Ether, srp
from tqdm import tqdm
from jinja2 import Environment, FileSystemLoader 

# default top ports to scan if none specified
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389]

def arp_scan(ip_range, timeout=3):
    """Discover live hosts via ARP."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    ans, _ = srp(ether/arp, timeout=timeout, verbose=0)
    hosts = []
    for sent, received in ans:
        ttl = received.ttl
        os_hint = "Windows" if ttl > 128 else "Linux/Unix"
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "os_hint": os_hint
        })
    return hosts

def tcp_scan_worker(port_queue, ip, open_ports, lock, timeout=1):
    """Thread worker: grab ports from queue and scan them."""
    while not port_queue.empty():
        port = port_queue.get()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                if s.connect_ex((ip, port)) == 0:
                    with lock:
                        open_ports.append(port)
            except Exception:
                pass
        port_queue.task_done()

def scan_ports(ip, ports, threads=50):
    """Scan given ports on a single IP using threading."""
    open_ports = []
    lock = threading.Lock()
    q = Queue()
    for p in ports:
        q.put(p)
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=tcp_scan_worker, args=(q, ip, open_ports, lock))
        t.daemon = True
        t.start()
    q.join()
    return sorted(open_ports)

def generate_reports(results, export_csv=None, export_json=None, html_report=None):
    """Export to CSV/JSON and render HTML report if requested."""
    if export_csv:
        keys = ["ip", "mac", "os_hint", "open_ports"]
        with open(export_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for host in results:
                writer.writerow({
                    **{k: host[k] for k in keys if k!="open_ports"},
                    "open_ports": ",".join(map(str, host["open_ports"]))
                })
        print(f"[+] CSV exported to {export_csv}")

    if export_json:
        with open(export_json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] JSON exported to {export_json}")

    if html_report:
        env = Environment(loader=FileSystemLoader("templates"))
        template = env.get_template("report_template.html")
        rendered = template.render(
            scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            hosts=results
        )
        with open(html_report, "w") as f:
            f.write(rendered)
        print(f"[+] HTML report generated: {html_report}")

def main():
    p = argparse.ArgumentParser(description="Advanced Network Scanner")
    p.add_argument("-t", "--target", required=True,
                   help="IP or range to scan (e.g. 192.168.1.0/24)")
    p.add_argument("-p", "--ports", default=",".join(map(str, TOP_PORTS)),
                   help="Comma‑separated list of ports (default: top 10 common)")
    p.add_argument("--csv", help="Export results to CSV file")
    p.add_argument("--json", help="Export results to JSON file")
    p.add_argument("--html", help="Export an HTML report")
    p.add_argument("--threads", type=int, default=50,
                   help="Number of threads for port scanning")
    args = p.parse_args()

    ports = [int(x) for x in args.ports.split(",") if x.strip().isdigit()]
    print(f"[+] Starting ARP scan on {args.target} …")
    hosts = arp_scan(args.target)
    print(f"[+] Found {len(hosts)} live hosts.\n")

    results = []
    for host in tqdm(hosts, desc="Port scanning hosts"):
        open_ports = scan_ports(host["ip"], ports, threads=args.threads)
        host["open_ports"] = open_ports
        results.append(host)

    # show summary
    print("\nScan complete. Summary:")
    for h in results:
        print(f" • {h['ip']} ({h['mac']}) [{h['os_hint']}] → Ports: {h['open_ports']}")

    # exports
    generate_reports(results,
                     export_csv=args.csv,
                     export_json=args.json,
                     html_report=args.html)

if __name__ == "__main__":
    main()

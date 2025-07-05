
# 🔍 Simple Advanced Network Scanner

**Course:** Information Security  
**Project:** Python-Based Network Scanner with ARP Discovery, Port Scanning & Reporting  
**Submitted by:** Ammar  
**Date:** January 2025  

---

## 📑 Table of Contents
1. Introduction  
2. Problem Statement  
3. Objectives  
4. Technology Stack  
5. System Design & Architecture  
6. Implementation Details  
   - 6.1 ARP Discovery  
   - 6.2 Multi-threaded TCP Port Scanning  
   - 6.3 OS Hinting via TTL  
   - 6.4 Progress Reporting  
   - 6.5 Export & HTML Reporting  
7. Usage & Demonstration  
8. Results & Sample Report  
9. Conclusion  
10. Future Enhancements  
11. References  

---

## 1. Introduction

Network reconnaissance is a foundational step in both penetration testing and network administration. This project presents a Python-based scanner that combines ARP host discovery with fast, multi-threaded TCP port scanning, enriched by OS hinting and automated report generation (CSV, JSON, and HTML).

---

## 2. Problem Statement

Many simple scanners either focus only on ARP discovery or only on port scanning, and rarely provide a polished report. This tool is designed to:
- Quickly find live hosts on a LAN  
- Scan arbitrary port ranges concurrently  
- Offer OS-level clues  
- Output human-readable and shareable reports  

---

## 3. Objectives

- Automate ARP-based host discovery on a given IP/range  
- Scan specified TCP ports on each discovered host using threads  
- Infer a basic OS hint from the TTL field  
- Display real-time progress via progress bars  
- Export results to CSV, JSON, and HTML via Jinja2 templates  

---

## 4. Technology Stack

| Component     | Purpose                             |
|--------------|-------------------------------------|
| Python 3      | Core programming language           |
| Scapy         | Low-level network packet crafting   |
| socket        | TCP port connection checks          |
| threading     | Concurrency                         |
| queue         | Manage thread-safe task dispatch    |
| tqdm          | Visual progress bars                |
| Jinja2        | HTML reporting templates            |
| SQLite (opt.) | Lightweight local storage           |

---

## 5. System Design & Architecture

```
┌──────────────────────────────┐
│      User invokes CLI       │
│  (target + ports + exports) │
└──────────────┬───────────────┘
               │
               ▼
       ┌───────────────┐
       │  ARP Scan     │───► Discover live hosts (IP, MAC, TTL)
       └───────────────┘
               │
               ▼
       ┌───────────────┐
       │ Port Scanner  │───► Multi-threaded scan for each host
       └───────────────┘
               │
               ▼
       ┌───────────────┐
       │ Collect Data  │───► {ip, mac, os_hint, open_ports}
       └───────────────┘
               │
     ┌─────────┼─────────┐
     ▼         ▼         ▼
 ┌───────┐ ┌────────┐ ┌────────┐
 │ CSV   │ │ JSON   │ │ HTML   │
 │ Export│ │ Export │ │ Report │
 └───────┘ └────────┘ └────────┘
```

---

## 6. Implementation Details

### 6.1 ARP Discovery
- Uses Scapy’s ARP + Ether layers to broadcast requests  
- Captures replies and extracts IP, MAC, TTL  
- TTL values used for basic OS hinting  

### 6.2 Multi-threaded TCP Port Scanning
- Uses `socket.connect_ex()` for each port  
- Queue-based threaded workers (default: 50 threads)  

### 6.3 OS Hinting via TTL
- TTL > 128 ➝ likely Windows  
- TTL ≤ 64 ➝ likely Linux/Unix  

### 6.4 Progress Reporting
- Uses `tqdm` to show scanning progress  

### 6.5 Export & HTML Reporting
- CSV: Simple tabular export  
- JSON: Full structured export  
- HTML: Templated output with styled table  

---

## 7. Usage & Demonstration

### 1. Install Dependencies
```bash
pip install scapy tqdm jinja2
```

### 2. Run Full Scan
```bash
python scanner.py \
  -t 192.168.1.0/24 \
  -p 22,80,443,3389 \
  --csv myscan.csv \
  --json myscan.json \
  --html report.html
```

### 3. View Reports
- `myscan.csv` ➝ Open in Excel  
- `myscan.json` ➝ For programmatic use  
- `report.html` ➝ Open in browser  

---

## 8. Results & Sample Report

| IP Address     | MAC Address         | OS Hint     | Open Ports       |
|----------------|---------------------|-------------|------------------|
| 192.168.1.10   | 00:11:22:33:44:55   | Linux/Unix  | 22, 80, 443      |
| 192.168.1.15   | 66:77:88:99:AA:BB   | Windows     | 3389             |

Output files (CSV, JSON, HTML) are included in the final package.

---

## 9. Conclusion

This Python-based scanner provides a fast, modular, and effective approach for LAN reconnaissance. It's ideal for IT admins and ethical hackers looking for a lightweight, CLI-based network visibility tool.

---

## 10. Future Enhancements

- ICMP/UDP support  
- Service banner grabbing  
- GUI frontend using Tkinter or Electron  
- Scheduled scans & alerts  
- Integration with threat feeds  

---

## 11. References

- Scapy Docs  
- Python socket Library  
- tqdm for CLI progress bars  
- Jinja2 for templating  

---

**Author:** Ammar Hanif  
**Institution:** University of South Asia  
**Semester:** BSCS Final Year Project – 2025  

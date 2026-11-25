# AegisScan — Educational Python Port Scanner

**AegisScan** is a zero-dependency, multi-threaded Python port scanner built specifically for cybersecurity students. Beyond showing which TCP ports are open, it grabs service banners, inspects TLS certificates, explains **why** each open port matters to an attacker, and shows **how to harden** it.

> **Ethical Notice:** Only scan `127.0.0.1`, your own home lab VMs, or targets where you have explicit written authorization.

## Features

- **Multi-threaded TCP Connect Engine** (`ThreadPoolExecutor`) with per-port latency measurement.
- **Smart Banner Grabbing & TLS Inspector** (detects HTTP servers, SSH/FTP greetings, TLS version, cipher, certificate issuer, and expiry).
- **Cybersecurity Risk & Hardening Engine** (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL` risk ratings + defender tips).
- **Student Learning Mode (`--learn`)** explaining DNS resolution, TCP 3-way handshake, threading, and banner grabbing.
- **Dark-Mode HTML & JSON Reports (`--out report.html`)** ready to attach to college assignments or lab reports.
- **Interactive Mode** when launched without arguments, plus a **Safe Local Practice Lab (`demo_lab.py`)**.

## Quick Start

```bash
# 1. Interactive beginner mode
python aegis_scan.py

# 2. Quick preset scan with student explanation
python aegis_scan.py 127.0.0.1 --ports quick --learn

# 3. Custom ports + HTML security audit report
python aegis_scan.py 127.0.0.1 -p 22,80,443,8000-8010 -o audit_report.html
```

## Safe Practice Lab (No External Targets Needed)

1. Terminal 1:
   ```bash
   python demo_lab.py
   ```
2. Copy the printed port list and run Terminal 2:
   ```bash
   python aegis_scan.py 127.0.0.1 -p <printed_ports> --learn -o demo_report.html
   ```

## Run Tests

```bash
python -m unittest discover -s tests -v
```

"""Terminal presentation, educational explanations, and JSON/HTML report export."""

import html
import json
import os
import sys
from typing import Dict

from .core import ScanSummary


class Palette:
    """ANSI color helper with automatic Windows console support."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled and sys.stdout.isatty()
        if self.enabled and os.name == "nt":
            os.system("")  # Enable VT100 escape sequences on modern Windows terminals

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def cyan(self, text: str) -> str:
        return self._wrap("96", text)

    def green(self, text: str) -> str:
        return self._wrap("92", text)

    def yellow(self, text: str) -> str:
        return self._wrap("93", text)

    def red(self, text: str) -> str:
        return self._wrap("91", text)

    def magenta(self, text: str) -> str:
        return self._wrap("95", text)

    def risk_badge(self, risk: str) -> str:
        if risk == "CRITICAL":
            return self.red(f"[{risk}]")
        if risk == "HIGH":
            return self.red(f"[{risk}]")
        if risk == "MEDIUM":
            return self.yellow(f"[{risk}]")
        if risk == "LOW":
            return self.green(f"[{risk}]")
        return self.cyan(f"[{risk}]")


def print_banner(pal: Palette) -> None:
    art = r"""
     _             _     ____
    / \   ___ __ _(_)___/ ___|  ___ __ _ _ __
   / _ \ / _ / _` | / __\___ \ / __/ _` | '_ \
  / ___ |  __| (_| | \__ \___) | (_| (_| | | | |
 /_/   \_\___\__, |_|___|____/ \___\__,_|_| |_|
             |___/   Cybersecurity Learning Scanner
"""
    print(pal.cyan(art))
    print(
        pal.yellow(
            "  [!] ETHICAL USE ONLY: Scan only localhost, lab VMs, or systems you have explicit permission to test.\n"
        )
    )


def print_learning_guide(pal: Palette) -> None:
    """Print a concise beginner-friendly breakdown of how this scanner works."""
    print(pal.bold(pal.magenta("=== HOW THIS PORT SCANNER WORKS (STUDENT GUIDE) ===")))
    lessons = [
        (
            "1. DNS Resolution",
            "Converts a domain like 'example.com' into an IPv4 address using socket.gethostbyname().",
        ),
        (
            "2. TCP 3-Way Handshake (Connect Scan)",
            "Our socket sends a SYN packet. If the port is OPEN, the target replies SYN-ACK and our OS completes ACK. "
            "If CLOSED, it replies RST. If a firewall drops packets silently, it times out (FILTERED).",
        ),
        (
            "3. Concurrency with Threads",
            "Scanning 1,000 ports one-by-one with a 1s timeout could take 16 minutes! "
            "ThreadPoolExecutor tests ~100 ports in parallel, finishing in a few seconds.",
        ),
        (
            "4. Banner Grabbing & TLS Inspection",
            "Once connected, many services reveal their software version (like 'SSH-2.0-OpenSSH'). "
            "On HTTPS/TLS ports, we inspect the SSL certificate's Common Name, Issuer, and Expiry.",
        ),
        (
            "5. Security Risk Assessment",
            "Finding an open port is just step 1 (Reconnaissance). Step 2 is asking: "
            "'Should this be public, is it encrypted, and how can an attacker abuse it?'",
        ),
    ]
    for title, body in lessons:
        print(f"  {pal.cyan(title)}\n    {body}")
    print()


def print_summary(summary: ScanSummary, pal: Palette) -> None:
    """Render scan results cleanly in the terminal."""
    print(pal.bold("\n=== SCAN RESULTS ==="))
    print(f"  Target        : {pal.cyan(summary.target)} ({summary.resolved_ip})")
    print(f"  Ports Scanned : {summary.total_ports}")
    print(f"  Open Ports    : {pal.green(str(len(summary.open_ports)))}")
    print(f"  Closed/Filter : {summary.closed_or_filtered}")
    print(f"  Duration      : {summary.duration_sec:.2f}s  |  Finished: {summary.timestamp}\n")

    if not summary.open_ports:
        print(pal.yellow("  No open TCP ports were detected in the specified range."))
        return

    header = f"  {'PORT':<11} {'SERVICE':<17} {'LATENCY':<10} {'RISK':<12} {'BANNER / TLS'}"
    print(pal.bold(header))
    print("  " + "-" * 82)
    for item in summary.open_ports:
        detail = item.tls_info or item.banner or "-"
        port_col = pal.green(f"{str(item.port) + '/tcp':<11}")
        risk_col = pal.risk_badge(item.risk) + " " * max(0, 12 - (len(item.risk) + 2))
        print(
            f"  {port_col} {item.service:<17} {str(item.latency_ms) + ' ms':<10} {risk_col} {detail}"
        )

    print(pal.bold("\n=== SECURITY INSIGHTS & HARDENING TIPS ==="))
    for item in summary.open_ports:
        print(f"  • {pal.bold(f'Port {item.port} ({item.service})')} {pal.risk_badge(item.risk)}")
        print(f"    {pal.dim('Risk:')} {item.why_it_matters}")
        print(f"    {pal.dim('Fix :')} {item.hardening_tip}")
    print()


def export_json(summary: ScanSummary, filepath: str) -> None:
    """Write scan summary to a formatted JSON file."""
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(summary.to_dict(), fh, indent=2)


def export_html(summary: ScanSummary, filepath: str) -> None:
    """Generate a standalone dark-mode HTML Security Audit Report."""
    risk_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for item in summary.open_ports:
        risk_counts[item.risk] = risk_counts.get(item.risk, 0) + 1

    rows_html = []
    for item in summary.open_ports:
        detail = html.escape(item.tls_info or item.banner or "No banner returned")
        badge_class = item.risk.lower()
        rows_html.append(
            f"""
            <tr>
              <td><span class="port-pill">{item.port}/tcp</span></td>
              <td><strong>{html.escape(item.service)}</strong></td>
              <td>{item.latency_ms} ms</td>
              <td><span class="badge {badge_class}">{html.escape(item.risk)}</span></td>
              <td>
                <div class="banner">{detail}</div>
                <div class="insight"><strong>Why it matters:</strong> {html.escape(item.why_it_matters)}</div>
                <div class="fix"><strong>Hardening:</strong> {html.escape(item.hardening_tip)}</div>
              </td>
            </tr>
            """
        )

    table_body = "\n".join(rows_html) if rows_html else (
        '<tr><td colspan="5" style="text-align:center;color:#94a3b8;padding:24px;">'
        "No open TCP ports detected in the scanned range.</td></tr>"
    )

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AegisScan Report - {html.escape(summary.target)}</title>
  <style>
    :root {{
      --bg: #0b1120;
      --card: #111827;
      --border: #1f2937;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --accent: #38bdf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 32px 20px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    .header {{
      display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
      border-bottom: 1px solid var(--border); padding-bottom: 18px; margin-bottom: 24px;
    }}
    h1 {{ margin: 0; font-size: 1.75rem; color: var(--accent); }}
    .meta {{ color: var(--muted); font-size: 0.9rem; }}
    .cards {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 14px; margin-bottom: 26px;
    }}
    .card {{
      background: var(--card); border: 1px solid var(--border);
      border-radius: 10px; padding: 14px 16px;
    }}
    .card .label {{ font-size: 0.78rem; text-transform: uppercase; color: var(--muted); }}
    .card .value {{ font-size: 1.5rem; font-weight: 700; margin-top: 4px; }}
    table {{
      width: 100%; border-collapse: collapse; background: var(--card);
      border: 1px solid var(--border); border-radius: 10px; overflow: hidden;
    }}
    th, td {{ padding: 14px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ background: #0f172a; font-size: 0.8rem; text-transform: uppercase; color: var(--muted); }}
    .port-pill {{
      background: #0f172a; border: 1px solid #334155; padding: 3px 8px;
      border-radius: 6px; font-family: monospace; color: #34d399; font-weight: 600;
    }}
    .badge {{
      display: inline-block; padding: 3px 9px; border-radius: 999px;
      font-size: 0.75rem; font-weight: 700;
    }}
    .critical {{ background: rgba(239, 68, 68, 0.18); color: #f87171; border: 1px solid #ef4444; }}
    .high {{ background: rgba(249, 115, 22, 0.18); color: #fb923c; border: 1px solid #f97316; }}
    .medium {{ background: rgba(234, 179, 8, 0.18); color: #facc15; border: 1px solid #eab308; }}
    .low {{ background: rgba(34, 197, 94, 0.18); color: #4ade80; border: 1px solid #22c55e; }}
    .info {{ background: rgba(56, 189, 248, 0.18); color: #38bdf8; border: 1px solid #38bdf8; }}
    .banner {{
      font-family: monospace; font-size: 0.85rem; color: #cbd5e1;
      background: #0b1220; padding: 6px 9px; border-radius: 6px; margin-bottom: 8px;
      word-break: break-word;
    }}
    .insight, .fix {{ font-size: 0.86rem; color: #cbd5e1; margin-top: 4px; }}
    .fix {{ color: #a7f3d0; }}
    footer {{ margin-top: 24px; text-align: center; font-size: 0.8rem; color: var(--muted); }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>AegisScan Security Audit Report</h1>
        <div class="meta">Target: <strong>{html.escape(summary.target)}</strong> ({html.escape(summary.resolved_ip)}) &bull; Scanned: {html.escape(summary.timestamp)}</div>
      </div>
      <div class="meta">Duration: {summary.duration_sec:.2f}s</div>
    </div>

    <div class="cards">
      <div class="card"><div class="label">Ports Scanned</div><div class="value">{summary.total_ports}</div></div>
      <div class="card"><div class="label">Open Ports</div><div class="value" style="color:#4ade80;">{len(summary.open_ports)}</div></div>
      <div class="card"><div class="label">Critical / High</div><div class="value" style="color:#f87171;">{risk_counts['CRITICAL'] + risk_counts['HIGH']}</div></div>
      <div class="card"><div class="label">Medium</div><div class="value" style="color:#facc15;">{risk_counts['MEDIUM']}</div></div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Port</th>
          <th>Service</th>
          <th>Latency</th>
          <th>Risk</th>
          <th>Banner / TLS &amp; Security Guidance</th>
        </tr>
      </thead>
      <tbody>
        {table_body}
      </tbody>
    </table>

    <footer>Generated by AegisScan &bull; Educational Cybersecurity Port Scanner (Authorized Testing Only)</footer>
  </div>
</body>
</html>
"""
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(document)

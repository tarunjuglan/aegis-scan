"""Unit and local integration tests for AegisScan."""

import json
import os
import tempfile
import unittest

from demo_lab import start_demo_lab
from scanner.core import run_scan
from scanner.intel import get_port_intel, parse_ports
from scanner.reporter import export_html, export_json


class TestPortParsing(unittest.TestCase):
    def test_custom_ranges_and_presets(self):
        self.assertEqual(parse_ports("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])
        self.assertIn(443, parse_ports("web"))
        self.assertIn(3306, parse_ports("db"))

    def test_invalid_port_raises(self):
        with self.assertRaises(ValueError):
            parse_ports("0")
        with self.assertRaises(ValueError):
            parse_ports("70000")
        with self.assertRaises(ValueError):
            parse_ports("100-50")


class TestIntel(unittest.TestCase):
    def test_known_and_unknown_ports(self):
        rdp = get_port_intel(3389)
        self.assertEqual(rdp.service, "RDP")
        self.assertEqual(rdp.risk, "CRITICAL")

        custom = get_port_intel(54321, fallback_service="CustomApp")
        self.assertEqual(custom.service, "CustomApp")
        self.assertEqual(custom.risk, "INFO")

        ssh_alt = get_port_intel(54322, banner="SSH-2.0-OpenSSH_9.6p1")
        self.assertEqual(ssh_alt.service, "SSH (Alt Port)")
        self.assertEqual(ssh_alt.risk, "LOW")


class TestLocalScanAndReports(unittest.TestCase):
    def test_scan_demo_lab_and_export_reports(self):
        servers, port_csv = start_demo_lab()
        try:
            open_ports = [srv[1] for srv in servers]
            # Pick one definitely unused port by closing a temporary socket or using open_ports + 1
            probe_ports = sorted(set(open_ports + [open_ports[-1] + 1]))

            summary = run_scan("127.0.0.1", probe_ports, threads=10, timeout=0.6)
            found_ports = [item.port for item in summary.open_ports]
            for expected in open_ports:
                self.assertIn(expected, found_ports)

            banners = " | ".join(item.banner for item in summary.open_ports)
            self.assertIn("SSH-2.0-OpenSSH_9.6p1", banners)
            self.assertIn("DemoLab FTP Server", banners)

            with tempfile.TemporaryDirectory() as tmpdir:
                json_path = os.path.join(tmpdir, "report.json")
                html_path = os.path.join(tmpdir, "report.html")

                export_json(summary, json_path)
                export_html(summary, html_path)

                with open(json_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                self.assertEqual(data["resolved_ip"], "127.0.0.1")
                self.assertGreaterEqual(data["open_count"], 3)

                with open(html_path, "r", encoding="utf-8") as fh:
                    html_text = fh.read()
                self.assertIn("AegisScan Security Audit Report", html_text)
                self.assertIn("127.0.0.1", html_text)
        finally:
            for srv, _, _ in servers:
                srv.shutdown()
                srv.server_close()


if __name__ == "__main__":
    unittest.main()

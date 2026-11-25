"""Safe local practice lab: starts harmless dummy TCP servers on 127.0.0.1 for testing AegisScan."""

import socketserver
import threading
import time


class BannerHandler(socketserver.BaseRequestHandler):
    banner_bytes = b""
    wait_for_client = False

    def handle(self):
        try:
            if self.wait_for_client:
                self.request.settimeout(1.0)
                try:
                    self.request.recv(512)
                except OSError:
                    pass
            self.request.sendall(self.banner_bytes)
        except OSError:
            pass


def _make_handler(banner: bytes, wait_for_client: bool = False):
    class CustomHandler(BannerHandler):
        banner_bytes = banner
        pass

    CustomHandler.wait_for_client = wait_for_client
    return CustomHandler


class ReusableTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_demo_lab():
    """Spin up 3 safe local demo services on unused high ports."""
    services = [
        (0, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-DemoLab\r\n", False, "Simulated SSH"),
        (0, b"220 DemoLab FTP Server (vsFTPd 3.0.5) ready\r\n", False, "Simulated FTP"),
        (
            0,
            b"HTTP/1.1 200 OK\r\nServer: AegisLab-MockHTTP/1.0\r\nContent-Length: 2\r\n\r\nOK",
            True,
            "Simulated HTTP",
        ),
    ]

    servers = []
    ports = []
    for port, banner, wait_client, label in services:
        srv = ReusableTCPServer(("127.0.0.1", port), _make_handler(banner, wait_client))
        actual_port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        servers.append((srv, actual_port, label))
        ports.append(str(actual_port))

    return servers, ",".join(ports)


if __name__ == "__main__":
    servers, port_csv = start_demo_lab()
    print("=== AegisScan Safe Local Practice Lab ===")
    for _, port, label in servers:
        print(f"  Listening on 127.0.0.1:{port} -> {label}")
    print("\nRun this in another terminal to test AegisScan safely:")
    print(f"  python aegis_scan.py 127.0.0.1 -p {port_csv} --learn -o demo_report.html")
    print("\nPress Ctrl+C to stop the lab...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down demo lab.")
        for srv, _, _ in servers:
            srv.shutdown()
            srv.server_close()

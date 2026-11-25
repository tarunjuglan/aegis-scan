"""Core TCP Connect scanning, banner grabbing, and TLS inspection engine."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
import socket
import ssl
import time
from typing import Callable, List, Optional

from .intel import HTTP_PORTS, TLS_PORTS, get_port_intel


@dataclass
class PortResult:
    """Structured result for a single open TCP port."""

    port: int
    state: str
    service: str
    latency_ms: float
    banner: str
    tls_info: str
    risk: str
    why_it_matters: str
    hardening_tip: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanSummary:
    """Complete scan metadata and discovered open ports."""

    target: str
    resolved_ip: str
    total_ports: int
    open_ports: List[PortResult]
    closed_or_filtered: int
    duration_sec: float
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "total_ports": self.total_ports,
            "open_count": len(self.open_ports),
            "closed_or_filtered": self.closed_or_filtered,
            "duration_sec": round(self.duration_sec, 3),
            "timestamp": self.timestamp,
            "open_ports": [p.to_dict() for p in self.open_ports],
        }


def resolve_target(target: str) -> str:
    """Resolve a hostname or IPv4 address to an IPv4 string."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target '{target}': {exc}") from exc


def _guess_os_service(port: int) -> str:
    """Use the OS service table as a fallback name for uncommon ports."""
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "Unknown"


def _clean_banner(raw: bytes, limit: int = 140) -> str:
    """Convert raw socket bytes into a safe, single-line printable preview."""
    text = raw.decode("utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    # For HTTP responses, pick status line + Server header if present
    preview = lines[0]
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            preview = f"{preview} | {line}"
            break
    printable = "".join(ch if 32 <= ord(ch) <= 126 else "." for ch in preview)
    return printable[:limit] + ("..." if len(printable) > limit else "")


def _grab_tls_info(ip: str, hostname: str, port: int, timeout: float) -> str:
    """Inspect TLS version, cipher, and certificate metadata when possible."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_ver = ssock.version() or "TLS"
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                cn = subject.get("commonName", "N/A")
                org = issuer.get("organizationName", issuer.get("commonName", "N/A"))
                expiry = cert.get("notAfter", "N/A")
                cipher_name = cipher[0] if cipher else "Unknown"
                return f"{tls_ver} ({cipher_name}) | CN={cn} | Issuer={org} | Expires={expiry}"
    except ssl.SSLCertVerificationError:
        # Fallback: connect without verification so self-signed certs are still reported safely
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    tls_ver = ssock.version() or "TLS"
                    cipher_name = cipher[0] if cipher else "Unknown"
                    return f"{tls_ver} ({cipher_name}) | Warning: Untrusted or self-signed certificate"
        except OSError:
            return ""
    except OSError:
        return ""


def _grab_banner(ip: str, hostname: str, port: int, timeout: float) -> str:
    """Attempt safe banner grabbing on an open TCP port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in HTTP_PORTS:
                req = f"HEAD / HTTP/1.0\r\nHost: {hostname}\r\nUser-Agent: AegisScan/1.0\r\n\r\n"
                sock.sendall(req.encode("ascii", errors="ignore"))
                data = sock.recv(512)
                return _clean_banner(data)

            # Wait briefly for servers that send a greeting banner (SSH, FTP, SMTP, Redis, etc.)
            try:
                data = sock.recv(512)
                if data:
                    return _clean_banner(data)
            except socket.timeout:
                pass

            # Gentle generic probe if the service expects client input first
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(512)
            return _clean_banner(data)
    except OSError:
        return ""


def scan_single_port(
    ip: str,
    hostname: str,
    port: int,
    timeout: float = 0.8,
    grab_banners: bool = True,
) -> Optional[PortResult]:
    """Perform a TCP Connect check on a single port; return PortResult if open, else None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        err = sock.connect_ex((ip, port))
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    except OSError:
        return None
    finally:
        sock.close()

    if err != 0:
        return None

    banner = ""
    tls_info = ""
    if grab_banners:
        if port in TLS_PORTS:
            tls_info = _grab_tls_info(ip, hostname, port, timeout=max(timeout, 1.5))
        else:
            banner = _grab_banner(ip, hostname, port, timeout=max(timeout, 1.0))

    intel = get_port_intel(port, fallback_service=_guess_os_service(port), banner=banner)
    return PortResult(
        port=port,
        state="OPEN",
        service=intel.service,
        latency_ms=elapsed_ms,
        banner=banner,
        tls_info=tls_info,
        risk=intel.risk,
        why_it_matters=intel.why_it_matters,
        hardening_tip=intel.hardening_tip,
    )


def run_scan(
    target: str,
    ports: List[int],
    threads: int = 100,
    timeout: float = 0.8,
    grab_banners: bool = True,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> ScanSummary:
    """Scan all requested TCP ports concurrently and return a ScanSummary."""
    resolved_ip = resolve_target(target)
    started = time.perf_counter()
    open_results: List[PortResult] = []
    total = len(ports)
    worker_count = max(1, min(threads, total))

    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = {
            pool.submit(scan_single_port, resolved_ip, target, port, timeout, grab_banners): port
            for port in ports
        }
        for future in as_completed(futures):
            completed += 1
            res = future.result()
            if res is not None:
                open_results.append(res)
            if progress_cb is not None:
                progress_cb(completed, total)

    open_results.sort(key=lambda r: r.port)
    duration = time.perf_counter() - started
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    return ScanSummary(
        target=target,
        resolved_ip=resolved_ip,
        total_ports=total,
        open_ports=open_results,
        closed_or_filtered=total - len(open_results),
        duration_sec=duration,
        timestamp=timestamp,
    )

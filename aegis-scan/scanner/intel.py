"""Port presets and cybersecurity risk intelligence database."""

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class PortIntel:
    """Security context for a well-known TCP port."""

    service: str
    risk: str  # LOW, MEDIUM, HIGH, CRITICAL, INFO
    why_it_matters: str
    hardening_tip: str


# Curated educational intelligence for common ports
PORT_INTEL: Dict[int, PortIntel] = {
    21: PortIntel(
        service="FTP",
        risk="HIGH",
        why_it_matters="Transmits usernames and passwords in plaintext; vulnerable to sniffing and anonymous login misconfigurations.",
        hardening_tip="Disable plain FTP; migrate to SFTP (port 22) or FTPS, and disallow anonymous access.",
    ),
    22: PortIntel(
        service="SSH",
        risk="LOW",
        why_it_matters="Encrypted remote shell, frequently targeted by automated credential brute-force bots.",
        hardening_tip="Disable password auth (use Ed25519 keys), disable root login, and enable Fail2Ban.",
    ),
    23: PortIntel(
        service="Telnet",
        risk="CRITICAL",
        why_it_matters="Completely unencrypted remote terminal; attackers on the network can read every keystroke and password.",
        hardening_tip="Turn off Telnet immediately and replace it with SSH.",
    ),
    25: PortIntel(
        service="SMTP",
        risk="MEDIUM",
        why_it_matters="Mail transfer port; misconfigured open relays can be abused for spam and phishing.",
        hardening_tip="Enforce TLS (STARTTLS), require authentication, and configure SPF/DKIM/DMARC.",
    ),
    53: PortIntel(
        service="DNS",
        risk="MEDIUM",
        why_it_matters="Exposed DNS resolvers can leak internal hostnames (zone transfers) or be abused in amplification DDoS.",
        hardening_tip="Restrict zone transfers (AXFR) and disable recursion on public-facing authoritative servers.",
    ),
    80: PortIntel(
        service="HTTP",
        risk="MEDIUM",
        why_it_matters="Unencrypted web traffic; susceptible to MitM interception and common web app vulnerabilities.",
        hardening_tip="Redirect all HTTP traffic to HTTPS (443) and add security headers (HSTS, CSP).",
    ),
    110: PortIntel(
        service="POP3",
        risk="HIGH",
        why_it_matters="Legacy email retrieval protocol sending credentials without encryption.",
        hardening_tip="Use POP3S (995) or IMAPS (993) with TLS enabled.",
    ),
    135: PortIntel(
        service="MSRPC",
        risk="HIGH",
        why_it_matters="Windows RPC endpoint mapper; exposes internal Windows services if reachable from the internet.",
        hardening_tip="Block port 135 at the perimeter firewall; restrict to trusted internal subnets.",
    ),
    139: PortIntel(
        service="NetBIOS-SSN",
        risk="HIGH",
        why_it_matters="Legacy Windows file/printer sharing protocol; leaks system names and shares.",
        hardening_tip="Disable NetBIOS over TCP/IP if not required and block at firewall.",
    ),
    143: PortIntel(
        service="IMAP",
        risk="HIGH",
        why_it_matters="Plaintext email access protocol if STARTTLS is not enforced.",
        hardening_tip="Switch to IMAPS (port 993) with TLS 1.2+.",
    ),
    443: PortIntel(
        service="HTTPS",
        risk="LOW",
        why_it_matters="Encrypted web service, though weak TLS ciphers, expired certs, or app bugs can still expose data.",
        hardening_tip="Enforce TLS 1.2/1.3, automate certificate renewal, and keep web frameworks patched.",
    ),
    445: PortIntel(
        service="SMB",
        risk="CRITICAL",
        why_it_matters="Windows file sharing; historically targeted by worms/ransomware (e.g., EternalBlue) and relay attacks.",
        hardening_tip="Never expose SMB to the public internet; disable SMBv1 and require SMB signing.",
    ),
    1433: PortIntel(
        service="MSSQL",
        risk="HIGH",
        why_it_matters="Microsoft SQL Server; exposed DB ports attract brute-force and SQL injection exploitation.",
        hardening_tip="Bind to localhost/private VLAN only and enforce TLS encryption.",
    ),
    1521: PortIntel(
        service="Oracle DB",
        risk="HIGH",
        why_it_matters="Oracle database listener; shouldn't be directly exposed outside application tiers.",
        hardening_tip="Isolate behind firewall rules allowing only application servers.",
    ),
    3306: PortIntel(
        service="MySQL",
        risk="HIGH",
        why_it_matters="Database service; direct internet exposure allows brute-force and version-specific exploits.",
        hardening_tip="Bind MySQL to 127.0.0.1 or internal VPC, use strong credentials, and require SSL.",
    ),
    3389: PortIntel(
        service="RDP",
        risk="CRITICAL",
        why_it_matters="Windows Remote Desktop; top entry vector for ransomware via brute-force or BlueKeep-style flaws.",
        hardening_tip="Place RDP behind a VPN, enable Network Level Authentication (NLA), and enforce MFA.",
    ),
    5432: PortIntel(
        service="PostgreSQL",
        risk="HIGH",
        why_it_matters="Database port; misconfigured pg_hba.conf can allow unauthorized remote access.",
        hardening_tip="Restrict listen_addresses, enforce scram-sha-256 auth, and firewall external access.",
    ),
    5900: PortIntel(
        service="VNC",
        risk="CRITICAL",
        why_it_matters="Graphical remote desktop often protected only by weak passwords and unencrypted by default.",
        hardening_tip="Tunnel VNC over an SSH tunnel or VPN; never expose port 5900 directly.",
    ),
    6379: PortIntel(
        service="Redis",
        risk="CRITICAL",
        why_it_matters="In-memory data store often deployed without authentication, allowing instant data theft or RCE.",
        hardening_tip="Bind to localhost, set a strong requirepass/ACL, and disable dangerous commands.",
    ),
    8000: PortIntel(
        service="HTTP-Alt / Dev",
        risk="MEDIUM",
        why_it_matters="Frequently used by dev servers (Django, FastAPI, Python http.server) with debug mode enabled.",
        hardening_tip="Ensure development servers are not exposed publicly and debug pages are off.",
    ),
    8080: PortIntel(
        service="HTTP-Proxy / Alt",
        risk="MEDIUM",
        why_it_matters="Common alternate web server, Tomcat admin, or proxy port.",
        hardening_tip="Remove default admin credentials and put behind a reverse proxy with HTTPS.",
    ),
    8443: PortIntel(
        service="HTTPS-Alt",
        risk="LOW",
        why_it_matters="Alternate TLS web port, often hosting management dashboards.",
        hardening_tip="Restrict management panels to admin IPs and use valid TLS certificates.",
    ),
    9200: PortIntel(
        service="Elasticsearch",
        risk="CRITICAL",
        why_it_matters="Search engine API; historically caused massive data leaks when left open without auth.",
        hardening_tip="Enable X-Pack security/TLS and keep port 9200 internal only.",
    ),
    27017: PortIntel(
        service="MongoDB",
        risk="CRITICAL",
        why_it_matters="NoSQL database; open instances without auth are prime targets for automated ransom bots.",
        hardening_tip="Enable authentication, bind to private IP, and block port 27017 externally.",
    ),
}

TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443}
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888, 3000, 5000}

PRESETS: Dict[str, List[int]] = {
    "quick": [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 1433, 3306, 3389, 5432, 5900, 6379,
        8000, 8080, 8443, 27017,
    ],
    "web": [80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000],
    "db": [1433, 1521, 3306, 5432, 6379, 9200, 27017],
    "top100": sorted({
        7, 9, 13, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
        113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
        513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
        1025, 1026, 1027, 1028, 1029, 1110, 1433, 1521, 1720, 1723, 1755, 1900,
        2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000,
        5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100,
        9200, 9999, 10000, 27017, 32768, 49152,
    }),
}


def get_port_intel(port: int, fallback_service: str = "Unknown", banner: str = "") -> PortIntel:
    """Return curated security intel by port number or banner fingerprint."""
    if port in PORT_INTEL:
        return PORT_INTEL[port]

    lower = banner.lower()
    if lower.startswith("ssh-"):
        base = PORT_INTEL[22]
        return PortIntel("SSH (Alt Port)", base.risk, base.why_it_matters, base.hardening_tip)
    if "ftp" in lower and lower.startswith("220"):
        base = PORT_INTEL[21]
        return PortIntel("FTP (Alt Port)", base.risk, base.why_it_matters, base.hardening_tip)
    if lower.startswith("http/"):
        base = PORT_INTEL[80]
        return PortIntel("HTTP (Alt Port)", base.risk, base.why_it_matters, base.hardening_tip)
    if "smtp" in lower and lower.startswith("220"):
        base = PORT_INTEL[25]
        return PortIntel("SMTP (Alt Port)", base.risk, base.why_it_matters, base.hardening_tip)

    return PortIntel(
        service=fallback_service,
        risk="INFO",
        why_it_matters="Custom or uncommon TCP service detected. Verify whether this port is intentionally exposed.",
        hardening_tip="Confirm which process owns this port (netstat / ss) and restrict access via firewall if unneeded.",
    )


def parse_ports(spec: str) -> List[int]:
    """
    Parse a port specification string like '22,80,443,8000-8010' or preset name.
    Raises ValueError on invalid port numbers or ranges.
    """
    spec = spec.strip().lower()
    if spec in PRESETS:
        return list(PRESETS[spec])
    if spec == "full":
        return list(range(1, 65536))

    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            pieces = part.split("-", 1)
            start, end = int(pieces[0]), int(pieces[1])
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Port out of range (1-65535): {p}")
            ports.add(p)

    if not ports:
        raise ValueError("No valid ports specified.")
    return sorted(ports)

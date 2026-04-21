"""
probe.py
Author: LOUAA AL MITHEAB
"""
import socket
import re
import time
import random

P_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

SIGS = [
    (r"SSH-(\d+\.\d+)-(\S+)", "ssh", 0.99, 2),
    (r"HTTP/[\d.]+ \d{3}", "http", 0.95, None),
    (r"Server:\s*(.+)", "http", 0.80, 1),
    (r"^\+OK", "pop3", 0.95, None),
    (r"^\* OK.*IMAP", "imap", 0.95, None),
    (r"^220[- ].*[Ss][Mm][Tt][Pp]", "smtp", 0.95, None),
    (r"^220[- ].*[Ff][Tt][Pp]", "ftp", 0.95, None),
    (r"^\xff[\xfb-\xfe]", "telnet", 0.85, None),
    (r"^RFB (\d+\.\d+)", "vnc", 0.99, 1),
    (r"\xffSMB|\xfeSMB", "smb", 0.95, None),
    (r"(?i)mysql_native_password|caching_sha2_password", "mysql", 0.95, None),
    (r"redis_version:([0-9.]+)", "redis", 0.95, 1),
    (r"^\+PONG", "redis", 0.90, None),
    (r"(?i)mongodb", "mongodb", 0.90, None),
    (r"^\x16\x03", "tls", 0.80, None),
    (r"\x03\x00\x00\x0b", "rdp", 0.90, None),
]

OS_HINTS = {
    "ubuntu": "Linux/Ubuntu", "debian": "Linux/Debian",
    "centos": "Linux/CentOS", "fedora": "Linux/Fedora",
    "freebsd": "FreeBSD", "openbsd": "OpenBSD",
    "cisco": "Cisco IOS", "routeros": "MikroTik",
    "iis": "Windows/IIS", "microsoft": "Windows",
}

H_PROBE = "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"

def grab(h: str, p: int, t: float = 3.0) -> dict:
    res = {
        "service": P_MAP.get(p, "unknown"),
        "version": None,
        "os_hint": None,
        "banner": None,
        "confidence": 0.3,
    }

    raw = do_req(h, p, t)
    if not raw: return res

    txt = raw.decode("utf-8", errors="replace")
    res["banner"] = txt[:200].strip().splitlines()[0] if txt.strip() else None

    for pat, svc, conf, vgrp in SIGS:
        m = re.search(pat, txt, re.MULTILINE)
        if not m: continue
        res["service"] = svc
        res["confidence"] = conf

        if vgrp and m.lastindex and m.lastindex >= vgrp:
            ver = m.group(vgrp).strip()
            res["version"] = ver[:64]

            if svc == "ssh":
                vl = ver.lower()
                for kw, osn in OS_HINTS.items():
                    if kw in vl:
                        res["os_hint"] = osn
                        break

        if svc == "http":
            s = re.search(r"(?i)Server:\s*(.+)", txt)
            if s: 
                ver_str = s.group(1).strip()[:64]
                res["version"] = ver_str
                if "IIS" in ver_str: res["os_hint"] = "Windows/IIS"
        break

    return res

def do_req(h: str, p: int, t: float):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(t)
        s.connect((h, p))
        time.sleep(random.uniform(0.3, 0.6))

        b = b""
        try: b = s.recv(4096)
        except socket.timeout: pass

        if not b:
            pb = b"\r\n"
            if p in (80, 8080, 8000, 8888):
                pb = H_PROBE.format(host=h).encode()
            elif p in (443, 8443):
                pb = b"\x16\x03\x01\x00\x00"
            elif p == 6379:
                pb = b"*1\r\n$4\r\nINFO\r\n"
            elif p == 3389:
                # RDP connection request
                pb = b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00"

            if pb:
                s.sendall(pb)
                time.sleep(0.5)
                try: b = s.recv(4096)
                except socket.timeout: pass

        s.close()
        return b or None
    except (OSError, socket.timeout, ConnectionRefusedError): 
        return None

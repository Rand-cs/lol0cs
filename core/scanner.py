"""
scanner.py
author: LOUAA AL MITHEAB
"""
import socket
import select
import time
import random
import threading
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict

from .probe import grab


P_PROFS: Dict[str, dict] = {
    "ghost":      {"b": 3.0,   "j": 1.2,  "brst": 0.04},
    "cautious":   {"b": 0.8,   "j": 0.5,  "brst": 0.10},
    "normal":     {"b": 0.18,  "j": 0.2,  "brst": 0.18},
    "aggressive": {"b": 0.03,  "j": 0.03, "brst": 0.40},
}

def get_delay(prof: str) -> float:
    c = P_PROFS.get(prof, P_PROFS["normal"])
    if random.random() < c["brst"]:
        return random.uniform(0.005, c["b"] * 0.25)
    d = random.gauss(c["b"], c["j"] * 0.4)
    return max(0.005, d)

# well known ports get hit first
VIP_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    3306, 3389, 5432, 6379, 8080, 8443, 27017,
}

def mix_ports(ports: List[int]) -> List[int]:
    vip = [p for p in ports if p in VIP_PORTS]
    others = [p for p in ports if p not in VIP_PORTS]
    
    others = sorted(others)
    sz = max(4, len(others) // 15)
    chunks = [others[i:i+sz] for i in range(0, len(others), sz)]
    for c in chunks: random.shuffle(c)
    random.shuffle(chunks)
    
    return vip + [p for c in chunks for p in c]

class Throttle:
    def __init__(self, p: str):
        self.p = p
        self.history = []
        self.m = 1.0

    def ack(self, ok: bool):
        self.history.append(ok)
        if len(self.history) > 40: self.history.pop(0)
        drops = self.history.count(False) / max(1, len(self.history))
        # back off if getting dropped too much
        if drops > 0.55:
            self.m = min(4.0, self.m * 1.25)
        elif drops < 0.15:
            self.m = max(1.0, self.m * 0.92)

    def wait_time(self) -> float:
        return get_delay(self.p) * self.m

def icmp_ping(ip: str, t: float = 1.5) -> bool:
    try:
        id_ = random.randint(1000, 60000)
        sq = random.randint(1, 255)
        payload = bytes(random.randint(0x20, 0x7e) for _ in range(32))

        hdr = struct.pack("!BBHHH", 8, 0, 0, id_, sq)
        buf = hdr + payload
        
        csum = 0
        tmp = buf if len(buf) % 2 == 0 else buf + b"\x00"
        for i in range(0, len(tmp), 2):
            csum += (tmp[i] << 8) + tmp[i+1]
        csum = (~((csum >> 16) + (csum & 0xFFFF))) & 0xFFFF
        
        pkt = struct.pack("!BBHHH", 8, 0, csum, id_, sq) + payload

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(t)
        s.sendto(pkt, (ip, 0))
        end = time.monotonic() + t
        while time.monotonic() < end:
            rd, _, _ = select.select([s], [], [], end - time.monotonic())
            if not rd: break
            d, _ = s.recvfrom(1024)
            if len(d) >= 28 and d[20] == 0:
                s.close()
                return True
        s.close()
    except (PermissionError, OSError): pass
    return False

def tcp_ping(ip: str, t: float = 1.5) -> bool:
    for p in (80, 443, 22, 8080):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(t)
            res = s.connect_ex((ip, p))
            s.close()
            if res in (0, 111): return True
        except OSError: pass
    return False

def is_alive(ip: str, t: float = 1.5) -> bool:
    return icmp_ping(ip, t) or tcp_ping(ip, t)

def scan_p(ip: str, p: int, t: float) -> dict:
    start = time.monotonic()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(t)
        r = s.connect_ex((ip, p))
        lat = (time.monotonic() - start) * 1000
        s.close()
        st = "open" if r == 0 else "closed" if r == 111 else "filtered"
    except socket.timeout:
        lat = (time.monotonic() - start) * 1000
        st = "filtered"
    except OSError:
        lat = (time.monotonic() - start) * 1000
        st = "filtered"

    return {"port": p, "state": st, "latency_ms": round(lat, 1), "service": "unknown", "version": None}

@dataclass
class ScanRes:
    ip: str
    hostname: Optional[str] = None
    up: bool = False
    ports: List[dict] = field(default_factory=list)
    t_scan: float = 0.0

    @property
    def opens(self):
        return [p for p in self.ports if p["state"] == "open"]

def get_ip(h: str) -> Optional[str]:
    try: return socket.gethostbyname(h)
    except socket.gaierror: return None

def get_rdns(ip: str) -> Optional[str]:
    try: return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror): return None

def run_scan(ip: str, ports: List[int], prof: str = "normal", t: float = 2.0, banner: bool = True, rdns: bool = True, w: int = 60, log_cb: Optional[Callable] = None) -> ScanRes:
    log_cb = log_cb or (lambda _: None)
    res = ScanRes(ip=ip, up=True)
    t0 = time.monotonic()

    if rdns: res.hostname = get_rdns(ip)

    ord_ports = mix_ports(ports)
    thrt = Throttle(prof)
    found = {}
    lk = threading.Lock()

    def do_work():
        with ThreadPoolExecutor(max_workers=w) as ex:
            f_map = {}
            for p in ord_ports:
                time.sleep(thrt.wait_time())
                f = ex.submit(scan_p, ip, p, t)
                f_map[f] = p

            for f in as_completed(f_map):
                try:
                    pr = f.result()
                    thrt.ack(pr["state"] != "filtered")
                    if pr["state"] == "open" and banner:
                        inf = grab(ip, pr["port"], t + 1.0)
                        pr.update({"service": inf.get("service", "unknown"), "version": inf.get("version"), "os_hint": inf.get("os_hint")})
                        ver_str = f"  {pr['version']}" if pr.get("version") else ""
                        log_cb(f"  {pr['port']:>5}/tcp  open  {pr['service']}{ver_str}")
                    with lk: found[pr["port"]] = pr
                except Exception: pass

    do_work()
    res.ports = sorted(found.values(), key=lambda x: x["port"])
    res.t_scan = time.monotonic() - t0
    return res

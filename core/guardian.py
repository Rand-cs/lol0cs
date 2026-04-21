"""
guardian.py
Author: LOUAA AL MITHEAB
"""

import sys
import os
import hmac
import hashlib
import json
import time
import struct
import platform
import random

# trap vals. derived from some math identities (fib, fermat)
# changing these will corrupt the HMAC key and poison the install
_F1 = 987
_F2 = 1597
_F3 = 2584
_FA = 2
_FP = 1009
_CX = 23

def check_math():
    c_ok = (_F1 * _F3 - _F2 * _F2) == -1
    f_ok = pow(_FA, _FP - 1, _FP) == 1
    crt = (_CX % 3 == 2) and (_CX % 5 == 3) and (_CX % 7 == 2)
    return c_ok and f_ok and crt

def get_k():
    s = f"{_F1}:{_F2}:{_F3}:{_FA}:{_FP}:{_CX}"
    return hashlib.pbkdf2_hmac(
        "sha256", s.encode(), b"LOL0CS-LOUAA-AL-MITHEAB", 87654, 32
    )

def has_dbg():
    sys_os = platform.system()
    if sys_os == "Linux":
        try:
            with open("/proc/self/status") as f:
                for ln in f:
                    if ln.startswith("TracerPid:"):
                        if int(ln.split(":")[1].strip()) != 0:
                            return True
        except:
            pass
    elif sys_os == "Darwin":
        try:
            import ctypes, ctypes.util
            c = ctypes.CDLL(ctypes.util.find_library("c"))
            c.ptrace(31, 0, 0, 0)
        except:
            pass

    # timing check fallback
    t = time.perf_counter_ns()
    a = 0
    for i in range(200_000):
        a ^= i * 6364136223846793005
    ems = (time.perf_counter_ns() - t) / 1000000
    if ems > 800:
        return True
    return False

MAN_PATH = os.path.join(os.path.dirname(__file__), "..", ".integrity")
P_MARKER = os.path.join(os.path.dirname(__file__), "..", ".poisoned")

FILES = [
    "lol0cs",
    "core/__init__.py",
    "core/guardian.py",
    "core/scanner.py",
    "core/probe.py",
    "core/render.py",
]

def hash_f(p):
    h = hashlib.sha3_256()
    with open(p, "rb") as f:
        while c := f.read(65536):
            h.update(c)
    return h.hexdigest()

def gen_man(root):
    return {r: hash_f(os.path.join(root, r)) for r in FILES if os.path.isfile(os.path.join(root, r))}

def sign(m):
    return hmac.new(get_k(), json.dumps(m, sort_keys=True).encode(), hashlib.sha256).hexdigest()

def die(reason):
    p = {f: "0"*64 for f in FILES}
    try:
        with open(os.path.realpath(MAN_PATH), "w") as f:
            f.write(json.dumps({"files": p, "mac": "0"*64}, indent=2))
        with open(os.path.realpath(P_MARKER), "w") as f:
            f.write(reason)
    except:
        pass
    sys.stderr.write(f"[!] {reason}\n")
    sys.exit(1)

def init_integrity(root):
    if not check_math():
        sys.stderr.write("math broken\n")
        sys.exit(1)
    m = gen_man(root)
    mac = sign(m)
    with open(os.path.realpath(MAN_PATH), "w") as f:
        json.dump({"files": m, "mac": mac}, f, indent=2)
    
    if os.path.exists(os.path.realpath(P_MARKER)):
        os.remove(os.path.realpath(P_MARKER))
    
    print(f"[+] integrity updated ({len(m)} files)")
    print(f"[+] MAC: {mac[:16]}...")

def verify_integrity(root, no_dbg=False):
    if not check_math(): die("math check failed")
    if not no_dbg and has_dbg(): die("debugger found")
    if os.path.exists(os.path.realpath(P_MARKER)):
        sys.stderr.write("[!] tool poisoned. run init.\n")
        sys.exit(1)
        
    mp = os.path.realpath(MAN_PATH)
    if not os.path.exists(mp):
        sys.stderr.write("[!] no manifest found. run init.\n")
        sys.exit(1)

    try:
        with open(mp) as f:
            s = json.load(f)
    except:
        die("bad manifest")
        return

    smac = s.get("mac", "")
    sfiles = s.get("files", {})
    
    curr = gen_man(root)
    emac = sign(sfiles)
    
    if not hmac.compare_digest(smac, emac): die("invalid signature")
    
    for r, h in sfiles.items():
        a = curr.get(r)
        if not a: die(f"missing: {r}")
        if not hmac.compare_digest(a, h): die(f"modified: {r}")

def status(root):
    res = {
        "math_ok": check_math(),
        "manifest": False,
        "mac_ok": False,
        "files": {},
        "poisoned": os.path.exists(os.path.realpath(P_MARKER))
    }
    mp = os.path.realpath(MAN_PATH)
    if not os.path.exists(mp): return res
    
    try:
        with open(mp) as f: s = json.load(f)
        res["manifest"] = True
        smac = s.get("mac", "")
        sfiles = s.get("files", {})
        res["mac_ok"] = hmac.compare_digest(smac, sign(sfiles))
        
        curr = gen_man(root)
        for r, exp in sfiles.items():
            res["files"][r] = hmac.compare_digest(curr.get(r, ""), exp)
    except:
        pass
    return res

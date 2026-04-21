"""
render.py
Author: LOUAA AL MITHEAB
"""
import sys
import os

color_on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

def _c(c, t):
    return f"\033[{c}m{t}\033[0m" if color_on else str(t)

def bld(t): return _c("1", t)
def dim(t): return _c("2", t)
def rd(t):  return _c("91", t)
def grn(t): return _c("92", t)
def ylw(t): return _c("93", t)
def cyn(t): return _c("96", t)
def wht(t): return _c("97", t)

sep_line = dim("─" * 58)

def show_tbl(hdrs, rws):
    w = [max(len(str(h)), max((len(str(r[i])) for r in rws), default=0)) for i, h in enumerate(hdrs)]
    w = [min(x, 40) for x in w]

    print(sep_line)
    
    parts = []
    for v, wd in zip(hdrs, w):
        parts.append(str(v).ljust(wd)[:wd])
    print("  " + "  ".join([bld(x) for x in parts]))
    
    print(sep_line)
    
    for rw in rws:
        p = []
        for v, wd in zip(rw, w):
            p.append(str(v).ljust(wd)[:wd])
        print("  " + "  ".join(p))
        
    print(sep_line)

def msg_ok(m): print(f"  {grn('[+]')} {m}")
def msg_in(m): print(f"  {cyn('[*]')} {m}")
def msg_wn(m): print(f"  {ylw('[!]')} {m}")
def msg_er(m): print(f"  {rd('[!]')} {m}", file=sys.stderr)

s_color = {"open": grn, "closed": dim, "filtered": ylw}

def show_host(ip, hname, is_up, ports, secs):
    s_h = f"  ({hname})" if hname else ""
    s_u = grn("up") if is_up else rd("down")
    print(f"\n  {bld('HOST')}  {wht(ip)}{dim(s_h)}  [{s_u}]")

    op = [p for p in ports if p["state"] == "open"]
    fl = [p for p in ports if p["state"] == "filtered"]
    cl = [p for p in ports if p["state"] == "closed"]

    print(dim(f"       {len(op)} open  |  {len(fl)} filtered  |  {len(cl)} closed\n"))

    if not ports:
        msg_wn("no ports to report")
        return

    rws = []
    for p in ports:
        cf = s_color.get(p["state"], dim)
        rws.append([
            cf(f"{p['port']}/tcp"),
            cf(p["state"]),
            p.get("service", "unknown"),
            (p.get("version") or "")[:32]
        ])

    show_tbl(["PORT", "STATE", "SERVICE", "VERSION"], rws)
    print(dim(f"      scan time {secs:.2f}s"))

def show_hdr(tgt, ps, tm, md, st):
    print(f"\n{bld(cyn('LOL0CS'))}{dim(' — network reconnaissance')}")
    print(sep_line)
    print(f"  target   : {bld(tgt)}")
    print(f"  ports    : {ps}")
    print(f"  timing   : {tm}")
    print(f"  mode     : {md}")
    print(f"  started  : {st}")
    print(sep_line + "\n")

def sum_up(th, uh, to, elps):
    print("\n" + sep_line)
    print(f"  {bld('done')}  {uh}/{th} host(s) up  |  {to} open port(s)  |  {elps:.1f}s total\n")

def show_stat(s):
    print(f"\n{bld('LOL0CS integrity status')}")
    print(sep_line)

    tck = lambda o: grn("PASS") if o else rd("FAIL")

    print(f"  math constants   : {tck(s['math_ok'])}")
    print(f"  manifest present : {tck(s['manifest'])}")
    print(f"  manifest MAC     : {tck(s['mac_ok'])}")
    print(f"  install poisoned : {rd('YES') if s['poisoned'] else grn('no')}\n")

    if s["files"]:
        print(f"  {'FILE':<35}  STATUS")
        print(dim(f"  {'─'*35}  ──────"))
        for p, ok in sorted(s["files"].items()):
            print(f"  {p:<35}  {grn('ok') if ok else rd('MODIFIED')}")

    print(sep_line + "\n")

def show_prb(h, p, inf):
    print(f"\n{bld(f'{h}:{p}')}")
    print(sep_line)
    for k, v in inf.items():
        if v: print(f"  {k:<16}: {v}")
    print(sep_line + "\n")

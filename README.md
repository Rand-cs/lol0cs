# LOL0CS

Network reconnaissance tool with self-integrity enforcement.  
**Author: LOUAA AL MITHEAB**

> For authorized use only — on networks you own or have written permission to test.

---

## Features

- Host discovery (ICMP + TCP fallback)
- Full port scan with configurable timing profiles
- Banner grabbing & service fingerprinting
- OS hinting from SSH banners
- Self-integrity system — detects tampering and poisons the install
- No third-party dependencies

---

## Requirements

- Python 3.11+
- Linux (Kali recommended) or macOS (Apple Silicon / Intel)
- Root/sudo for ICMP ping (TCP fallback works without it)

---

## Install

```bash
git clone https://github.com/Rand-cs/lol0cs
cd lol0cs
bash install.sh
```

To also make it available system-wide:

```bash
sudo bash install.sh --link
# then use from anywhere:
lol0cs scan 192.168.1.1
```

---

## Commands

```
lol0cs init                        regenerate integrity manifest
lol0cs version                     version info
lol0cs status                      integrity check report
lol0cs host   <target>             host discovery only
lol0cs probe  <target> <port>      detailed single-port fingerprint
lol0cs scan   <target> [options]   full port scan
lol0cs help                        show help
```

---

## Scan Examples

```bash
# single host, default settings
lol0cs scan 192.168.1.1

# subnet scan, quiet mode
lol0cs scan 192.168.1.0/24 -q

# specific ports, cautious timing
lol0cs scan 10.0.0.1 -p 22,80,443,3306 -t cautious

# range scan, skip ping, show all ports
lol0cs scan 10.0.0.1-20 --no-ping --show-all

# ghost mode — near-invisible
lol0cs scan 10.0.0.1 -p top -t ghost
```

---

## Scan Options

| Flag | Default | Description |
|------|---------|-------------|
| `-p` | `top` | Port spec: `top`, `all`, `22,80`, `1-1024`, mixed |
| `-t` | `normal` | Timing: `ghost`, `cautious`, `normal`, `aggressive` |
| `--timeout` | `2.0` | Per-port timeout (seconds) |
| `--workers` | `60` | Concurrent threads |
| `--no-ping` | off | Skip host discovery |
| `--no-banner` | off | Skip service detection |
| `--no-rdns` | off | Skip reverse DNS |
| `--show-all` | off | Include closed/filtered ports |
| `-q` | off | Quiet — suppress per-port output |

---

## Timing Profiles

| Profile | Avg delay | Use case |
|---------|-----------|----------|
| `ghost` | ~3s | Near-invisible, IDS evasion |
| `cautious` | ~0.8s | Low-noise scans |
| `normal` | ~0.18s | Default balanced |
| `aggressive` | ~0.03s | Internal lab use |

---

## Integrity System

LOL0CS verifies its own source files on every run.

Three checks happen before any scan:

1. **Math constants** — number-theoretic identities (Fibonacci/Cassini, Fermat, CRT)
2. **File hashes** — SHA3-256 of all source files vs a signed manifest
3. **Debugger detection** — TracerPid on Linux, ptrace on macOS, timing fallback

If any check fails, the manifest is poisoned and the tool is disabled.  
To restore after a clean reinstall:

```bash
lol0cs init
```

---

## License

MIT — free to use, modify, and distribute.  
Use responsibly and legally.


## Credits
Developed by **LOUAA AL MITHEAB** as a study on self-healing software and network reconnaissance.

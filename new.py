"""
Cloudflare IP Scanner + Remnawave Host Updater
----------------------------------------------
Scans Cloudflare IP ranges via traceroute, finds reachable IPs,
then updates all Remnawave hosts with a diverse selection of those IPs.
"""

import argparse
import ipaddress
import platform
import random
import re
import signal
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ─── CONFIG ────────────────────────────────────────────────────────────────────
PANEL_URL   = "https://your-panel.example.com"  # ← آدرس پنل رمناویو
PANEL_TOKEN = "YOUR_SECRET_TOKEN"               # ← توکن Bearer

RANGES_FILE = "ranges.txt"
OUTPUT_FILE = "reachable_hosts.txt"
THREADS     = 128
TIMEOUT     = 1    # seconds per traceroute hop
PICK_COUNT  = 10   # IPs to assign per host (from different /24 ranges)
# ───────────────────────────────────────────────────────────────────────────────

IS_WINDOWS = platform.system().lower() == "windows"
stop_event = threading.Event()


def _signal_handler(sig, frame):
    print("\n[i] Ctrl+C — stopping…")
    stop_event.set()

signal.signal(signal.SIGINT, _signal_handler)


# ══════════════════════════════════════════════════════════════════════════════
#  SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def last_hop(ip: str, timeout: int) -> str | None:
    """Run traceroute and return the last responding hop IP, or None."""
    try:
        if IS_WINDOWS:
            cmd = ["tracert", "-d", "-h", "30", "-w", str(timeout * 1000), ip]
            lines = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, universal_newlines=True
            ).splitlines()[2:]
        else:
            cmd = ["traceroute", "-n", "-m", "30", "-w", str(timeout), ip]
            lines = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, universal_newlines=True
            ).splitlines()[1:]
    except subprocess.CalledProcessError:
        return None

    hops = [
        re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", line)[-1]
        for line in lines
        if "*" not in line and re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", line)
    ]
    return hops[-1] if hops else None


def expand_to_24(cidrs: list[str]) -> list[str]:
    """Expand any CIDR list to a sorted, deduplicated set of /24 subnets."""
    subs: set[str] = set()
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.prefixlen < 24:
            subs.update(s.with_prefixlen for s in net.subnets(new_prefix=24))
        elif net.prefixlen == 24:
            subs.add(net.with_prefixlen)
        else:
            subs.add(net.supernet(new_prefix=24).with_prefixlen)
    return sorted(subs, key=lambda x: ipaddress.ip_network(x).network_address)


def _sample(hosts: list) -> list:
    """Pick ~5 representative indices from a host list."""
    n = len(hosts)
    return [hosts[i] for i in sorted({0, min(1, n-1), n//2, max(0, n-2), n-1})]


def scan_subnet(cidr: str, timeout: int, sample_mode: bool,
                quiet: bool, out_f) -> list[str]:
    """Scan one /24; a host is live if the traceroute's final hop equals its IP."""
    if stop_event.is_set():
        return []
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        if not quiet:
            print(f"[!] Invalid CIDR {cidr}: {exc}")
        return []

    hosts = list(net.hosts())
    if sample_mode:
        hosts = _sample(hosts)

    if not quiet:
        print(f"[>>] {cidr}  ({len(hosts)} hosts)")

    found = []
    for ip in hosts:
        if stop_event.is_set():
            break
        if last_hop(str(ip), timeout) == str(ip):
            if not quiet:
                print(f"[+] {ip}")
            out_f.write(f"{ip}\n")
            out_f.flush()
            found.append(str(ip))
    return found


def run_scan(ranges_file: str, output_file: str, threads: int,
             timeout: int, sample_mode: bool, quiet: bool) -> list[str]:
    try:
        with open(ranges_file) as f:
            cidrs = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        print(f"[!] Ranges file '{ranges_file}' not found.")
        sys.exit(1)

    if not cidrs:
        print("[!] No CIDRs in ranges file.")
        sys.exit(1)

    subnets = expand_to_24(cidrs)
    if not quiet:
        print(f"[i] {len(cidrs)} ranges → {len(subnets)} /24 subnets  "
              f"[{'sample' if sample_mode else 'full'} mode, {threads} threads]\n")

    all_found: list[str] = []
    with open(output_file, "w") as out_f, \
         ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(scan_subnet, cidr, timeout, sample_mode, quiet, out_f): cidr
            for cidr in subnets
        }
        for fut in as_completed(futures):
            if stop_event.is_set():
                break
            all_found.extend(fut.result())

    print(f"\n✅ Scan done — {len(all_found)} reachable IPs saved to '{output_file}'")
    return all_found


# ══════════════════════════════════════════════════════════════════════════════
#  HOST UPDATER
# ══════════════════════════════════════════════════════════════════════════════

def pick_diverse_ips(ips: list[str], count: int) -> list[str]:
    """Pick one random IP per /24 range, shuffled, up to `count`."""
    buckets: dict[str, list[str]] = {}
    for ip in ips:
        try:
            key = str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
            buckets.setdefault(key, []).append(ip)
        except ValueError:
            continue
    keys = list(buckets.keys())
    random.shuffle(keys)
    selected = [random.choice(buckets[k]) for k in keys[:count]]
    random.shuffle(selected)
    return selected


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def api_get_hosts(base_url: str, token: str) -> list[dict]:
    r = requests.get(f"{base_url}/api/hosts", headers=_headers(token), timeout=15)
    r.raise_for_status()
    return r.json()["response"]


def api_update_host(base_url: str, token: str, host: dict, address: str) -> None:
    # Nullable string fields: only include if non-null in the original host
    nullable_str = {"path", "sni", "host", "alpn", "fingerprint",
                    "serverDescription", "tag", "vlessRouteId", "xrayJsonTemplateUuid"}

    payload: dict = {
        "uuid":                       host["uuid"],
        "inbound":                    host["inbound"],
        "remark":                     host["remark"],
        "address":                    address,
        "port":                       host["port"],
        "isDisabled":                 host["isDisabled"],
        "securityLayer":              host["securityLayer"],
        "xHttpExtraParams":           host["xHttpExtraParams"],
        "muxParams":                  host["muxParams"],
        "sockoptParams":              host["sockoptParams"],
        "finalMask":                  host["finalMask"],
        "isHidden":                   host["isHidden"],
        "overrideSniFromAddress":     host["overrideSniFromAddress"],
        "keepSniBlank":               host["keepSniBlank"],
        "allowInsecure":              host["allowInsecure"],
        "shuffleHost":                host["shuffleHost"],
        "mihomoX25519":               host["mihomoX25519"],
        "nodes":                      host["nodes"],
        "excludedInternalSquads":     host["excludedInternalSquads"],
        "excludeFromSubscriptionTypes": host["excludeFromSubscriptionTypes"],
    }
    for field in nullable_str:
        if host.get(field) is not None:
            payload[field] = host[field]

    h = {**_headers(token), "Content-Type": "application/json"}
    r = requests.patch(f"{base_url}/api/hosts", json=payload, headers=h, timeout=15)
    r.raise_for_status()


def run_update(ips: list[str], base_url: str, token: str, count: int) -> None:
    if not ips:
        print("[!] No IPs available — skipping host update.")
        return

    selected = pick_diverse_ips(ips, count)
    if not selected:
        print("[!] Could not pick IPs from diverse /24 ranges.")
        return

    address_str = ",".join(selected)
    print(f"\n[i] {len(selected)} IPs selected (one per /24 range):")
    print(f"    {address_str}\n")

    print("[i] Fetching Remnawave hosts…")
    try:
        hosts = api_get_hosts(base_url, token)
    except Exception as exc:
        print(f"[!] Could not fetch hosts: {exc}")
        return

    print(f"[i] {len(hosts)} host(s) found. Updating…\n")
    ok = 0
    for host in hosts:
        name = host.get("remark") or host["uuid"]
        try:
            api_update_host(base_url, token, host, address_str)
            print(f"[+] {name}")
            ok += 1
        except requests.HTTPError as exc:
            print(f"[!] {name}: {exc.response.status_code} {exc.response.text}")
        except Exception as exc:
            print(f"[!] {name}: {exc}")

    print(f"\n✅ {ok}/{len(hosts)} host(s) updated.")


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan Cloudflare IPs via traceroute, then update Remnawave hosts."
    )
    parser.add_argument("-i", "--input",   default=RANGES_FILE,
                        help=f"CIDR ranges file  (default: {RANGES_FILE})")
    parser.add_argument("-o", "--output",  default=OUTPUT_FILE,
                        help=f"Reachable IPs file (default: {OUTPUT_FILE})")
    parser.add_argument("-t", "--threads", type=int, default=THREADS,
                        help=f"Parallel threads   (default: {THREADS})")
    parser.add_argument("-w", "--timeout", type=int, default=TIMEOUT,
                        help=f"Traceroute timeout per hop in seconds (default: {TIMEOUT})")
    parser.add_argument("-n", "--count",   type=int, default=PICK_COUNT,
                        help=f"IPs to assign per host (default: {PICK_COUNT})")
    parser.add_argument("-s", "--sample",  action="store_true",
                        help="Sample ~5 hosts per /24 instead of all 254")
    parser.add_argument("-q", "--quiet",   action="store_true",
                        help="Suppress per-IP output")
    parser.add_argument("--scan-only",    action="store_true",
                        help="Scan only; do not update Remnawave hosts")
    parser.add_argument("--update-only",  action="store_true",
                        help="Skip scan; update hosts from existing output file")
    args = parser.parse_args()

    base_url = PANEL_URL.rstrip("/")

    if args.update_only:
        try:
            with open(args.output) as f:
                ips = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            print(f"[!] '{args.output}' not found. Run a scan first.")
            sys.exit(1)
        run_update(ips, base_url, PANEL_TOKEN, args.count)
        return

    ips = run_scan(args.input, args.output, args.threads,
                   args.timeout, args.sample, args.quiet)

    if not args.scan_only:
        run_update(ips, base_url, PANEL_TOKEN, args.count)


if __name__ == "__main__":
    main()

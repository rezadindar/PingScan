"""
Cloudflare IP Scanner + Remnawave Host Updater
----------------------------------------------
Scans Cloudflare IP ranges via traceroute, finds reachable IPs,
then updates all Remnawave hosts with a diverse selection of those IPs.
"""

import argparse
import ipaddress
import os
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
#  SCANNER  (از new.py — دست نخورده + refactor جزئی)
# ══════════════════════════════════════════════════════════════════════════════

def last_hop(ip, timeout=2):
    """Run tracert/traceroute and return the last responding hop IP, or None."""
    try:
        if IS_WINDOWS:
            cmd = ['tracert', '-d', '-h', '30', '-w', str(int(timeout * 1000)), ip]
            lines = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, universal_newlines=True
            ).splitlines()[2:]
        else:
            cmd = ['traceroute', '-n', '-m', '30', '-w', str(timeout), ip]
            lines = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, universal_newlines=True
            ).splitlines()[1:]
    except subprocess.CalledProcessError:
        return None

    hops = []
    for line in lines:
        if '*' in line:
            continue
        ips = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", line)
        if ips:
            hops.append(ips[-1])
    return hops[-1] if hops else None


def sample_hosts(hosts):
    lst = list(hosts)
    n = len(lst)
    if n == 0:
        return []
    idx = sorted({0, min(1, n-1), n//2, max(0, n-2), n-1})
    return [lst[i] for i in idx]


def scan_cidr(cidr, timeout, quiet, sample_mode, out_f):
    """Scan /24: reachable if last hop matches the IP."""
    if stop_event.is_set():
        return []
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        if not quiet:
            print(f"[!] Invalid CIDR {cidr}: {e}")
        return []
    hosts = sample_hosts(net.hosts()) if sample_mode else list(net.hosts())
    if not quiet:
        print(f"[>>] Scanning {cidr} ({len(hosts)} hosts)")
    reachable = []
    for ip in hosts:
        if stop_event.is_set():
            break
        hop = last_hop(str(ip), timeout)
        if hop == str(ip):
            if not quiet:
                print(f"[+] Reachable: {ip}")
            out_f.write(f"{ip}\n")
            out_f.flush()
            reachable.append(str(ip))
    return reachable


def load_ranges(path):
    if not os.path.isfile(path):
        print(f"[!] Input file '{path}' not found.")
        sys.exit(1)
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith('#')]


def expand_to_24(cidrs):
    subs = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.prefixlen < 24:
            subs.extend([s.with_prefixlen for s in net.subnets(new_prefix=24)])
        elif net.prefixlen == 24:
            subs.append(net.with_prefixlen)
        else:
            subs.append(net.supernet(new_prefix=24).with_prefixlen)
    return sorted(set(subs), key=lambda x: ipaddress.ip_network(x).network_address)


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]


def run_scan(ranges_file, output_file, threads, batch_size, timeout, sample_mode, quiet):
    """Run the full scan and return list of reachable IPs."""
    cidrs = load_ranges(ranges_file)
    if not cidrs:
        print("[!] No valid CIDRs.")
        sys.exit(1)

    subnets = expand_to_24(cidrs)
    if not quiet:
        print(f"[i] {len(cidrs)} ranges → {len(subnets)} /24 subnets | "
              f"sample={'ON' if sample_mode else 'OFF'}")

    results = set()
    with open(output_file, 'w') as out_f:
        for idx, batch in enumerate(chunks(subnets, batch_size), 1):
            if stop_event.is_set():
                break
            if not quiet:
                total = len(subnets)
                start = (idx - 1) * batch_size + 1
                end = min(idx * batch_size, total)
                print(f"\n[i] Batch {idx}: subnets {start}-{end} of {total}")
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {
                    ex.submit(scan_cidr, cidr, timeout, quiet, sample_mode, out_f): cidr
                    for cidr in batch
                }
                for fut in as_completed(futures):
                    if stop_event.is_set():
                        break
                    results.update(fut.result())

    print(f"\n✅ Scan complete. {len(results)} reachable hosts saved to '{output_file}'")
    return list(results)


# ══════════════════════════════════════════════════════════════════════════════
#  HOST UPDATER  (از update_hosts.py)
# ══════════════════════════════════════════════════════════════════════════════

def pick_ips_from_diverse_ranges(ips, count=10):
    """Pick one random IP from each unique /24 range, up to `count` ranges (random order)."""
    ranges = {}
    for ip in ips:
        try:
            net = str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
            ranges.setdefault(net, []).append(ip)
        except ValueError:
            continue
    keys = list(ranges.keys())
    random.shuffle(keys)
    selected = [random.choice(ranges[k]) for k in keys[:count]]
    random.shuffle(selected)
    return selected


def get_all_hosts(base_url, token):
    r = requests.get(f"{base_url}/api/hosts",
                     headers={"Authorization": f"Bearer {token}"}, timeout=15)
    r.raise_for_status()
    return r.json()["response"]


def update_host_address(base_url, token, host, address_str):
    nullable_str_fields = {"path", "sni", "host", "alpn", "fingerprint",
                           "serverDescription", "tag", "vlessRouteId", "xrayJsonTemplateUuid"}
    payload = {
        "uuid": host["uuid"],
        "inbound": host["inbound"],
        "remark": host["remark"],
        "address": address_str,
        "port": host["port"],
        "isDisabled": host["isDisabled"],
        "securityLayer": host["securityLayer"],
        "xHttpExtraParams": host["xHttpExtraParams"],
        "muxParams": host["muxParams"],
        "sockoptParams": host["sockoptParams"],
        "finalMask": host["finalMask"],
        "isHidden": host["isHidden"],
        "overrideSniFromAddress": host["overrideSniFromAddress"],
        "keepSniBlank": host["keepSniBlank"],
        "allowInsecure": host["allowInsecure"],
        "shuffleHost": host["shuffleHost"],
        "mihomoX25519": host["mihomoX25519"],
        "nodes": host["nodes"],
        "excludedInternalSquads": host["excludedInternalSquads"],
        "excludeFromSubscriptionTypes": host["excludeFromSubscriptionTypes"],
    }
    for field in nullable_str_fields:
        if host.get(field) is not None:
            payload[field] = host[field]
    r = requests.patch(f"{base_url}/api/hosts", json=payload,
                       headers={"Authorization": f"Bearer {token}",
                                "Content-Type": "application/json"}, timeout=15)
    r.raise_for_status()
    return r.json()["response"]


def run_update(ips, base_url, token, count):
    """Pick diverse IPs and update all Remnawave hosts."""
    if not ips:
        print("[!] No IPs available — skipping host update.")
        return

    selected = pick_ips_from_diverse_ranges(ips, count)
    if not selected:
        print("[!] Could not select IPs from diverse ranges.")
        return

    address_str = ",".join(selected)
    print(f"[i] Selected {len(selected)} IPs from different /24 ranges:")
    print(f"    {address_str}\n")

    print("[i] Fetching hosts from Remnawave...")
    try:
        hosts = get_all_hosts(base_url, token)
    except Exception as e:
        print(f"[!] Could not fetch hosts: {e}")
        return

    print(f"[i] {len(hosts)} host(s) found.\n")
    ok = 0
    for host in hosts:
        remark = host.get("remark") or host["uuid"]
        try:
            update_host_address(base_url, token, host, address_str)
            print(f"[+] Updated: {remark}")
            ok += 1
        except requests.HTTPError as e:
            print(f"[!] Failed to update '{remark}': {e.response.status_code} {e.response.text}")
        except Exception as e:
            print(f"[!] Error updating '{remark}': {e}")

    print(f"\n✅ Done. {ok}/{len(hosts)} host(s) updated.")


# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Scan Cloudflare IPs via traceroute, then update Remnawave hosts."
    )
    parser.add_argument('-i', '--input',   default=RANGES_FILE,
                        help=f"CIDR ranges file (default: {RANGES_FILE})")
    parser.add_argument('-o', '--output',  default=OUTPUT_FILE,
                        help=f"Reachable IPs output file (default: {OUTPUT_FILE})")
    parser.add_argument('-t', '--threads', type=int, default=THREADS,
                        help=f"Parallel threads (default: {THREADS})")
    parser.add_argument('-b', '--batch',   type=int, default=8,
                        help="Subnets per batch (default: 8)")
    parser.add_argument('-w', '--timeout', type=int, default=TIMEOUT,
                        help=f"Traceroute timeout per hop in seconds (default: {TIMEOUT})")
    parser.add_argument('-n', '--count',   type=int, default=PICK_COUNT,
                        help=f"IPs to assign per host from diverse ranges (default: {PICK_COUNT})")
    parser.add_argument('-s', '--sample',  action='store_true',
                        help="Sample ~5 hosts per /24 instead of all 254")
    parser.add_argument('-q', '--quiet',   action='store_true',
                        help="Suppress per-IP output")
    parser.add_argument('--scan-only',    action='store_true',
                        help="Only scan; do not update Remnawave hosts")
    parser.add_argument('--update-only',  action='store_true',
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

    ips = run_scan(args.input, args.output, args.threads, args.batch,
                   args.timeout, args.sample, args.quiet)

    if not args.scan_only:
        run_update(ips, base_url, PANEL_TOKEN, args.count)


if __name__ == "__main__":
    main()

import os
import argparse
import ipaddress
import logging
import random
import signal
import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import conf, IP, ICMP, sr1

# Scapy and logging configuration
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)
conf.verb = 0
conf.checkIPaddr = False

# Graceful shutdown flag and Scapy lock
stop_scanning = False
print_lock = threading.Lock()
scapy_lock = threading.Lock()

def signal_handler(sig, frame):
    global stop_scanning
    with print_lock:
        logger.info("\nCtrl+C received. Stopping...")
    stop_scanning = True
signal.signal(signal.SIGINT, signal_handler)

def ping_time(ip: str, timeout: float = 1.0, attempts: int = 3) -> (bool, float):
    """Send ICMP Echo Requests and measure RTT."""
    ip_str = str(ip)
    rtts = []
    for _ in range(attempts):
        if stop_scanning:
            break
        with scapy_lock:
            pkt = IP(dst=ip_str)/ICMP(id=random.randint(0, 0xFFFF), seq=random.randint(0, 0xFFFF))
            try:
                del conf.netcache.arp_cache[ip_str]
            except KeyError:
                pass
            t0 = time.perf_counter()
            resp = sr1(pkt, timeout=timeout, verbose=False)
            t1 = time.perf_counter()
        if resp is not None:
            rtts.append((t1 - t0) * 1000)
    if rtts:
        return True, sum(rtts) / len(rtts)
    return False, None

def icmp_timestamp(ip: str, timeout: float = 1.0, attempts: int = 2) -> bool:
    """Send ICMP Timestamp Requests and check for replies."""
    ip_str = str(ip)
    for _ in range(attempts):
        if stop_scanning:
            break
        with scapy_lock:
            pkt = IP(dst=ip_str)/ICMP(type=13, id=random.randint(0, 0xFFFF), seq=random.randint(0, 0xFFFF))
            try:
                del conf.netcache.arp_cache[ip_str]
            except KeyError:
                pass
            resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp and resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 14:
            return True
    return False

def check_http_port(ip: str, port: int, timeout: float) -> bool:
    """Check if a TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False

def sample_hosts(hosts, sample: bool):
    """Sample hosts from a subnet if enabled."""
    h = list(hosts)
    if not sample or len(h) <= 5:
        return h
    n = len(h)
    idx = sorted({0, 1, n//2, n-2, n-1})
    return [h[i] for i in idx]

def scan_host(ip: str, timeout: float, rtt_threshold: float, require_http: bool,
              http_port: int, ping_attempts: int, ts_attempts: int) -> (str, str):
    """Scan a host and determine if it's alive."""
    try:
        if stop_scanning:
            return None, "Stopped"
        ping_ok, rtt = ping_time(ip, timeout, ping_attempts)
        if not ping_ok:
            with print_lock:
                logger.warning(f"{ip} | FAIL | reason=Not Pingable")
            return None, "Not Pingable"
        if rtt > rtt_threshold:
            with print_lock:
                logger.warning(f"{ip} | FAIL | reason=RTT too high ({rtt:.1f}ms > {rtt_threshold}ms)")
            return None, "RTT too high"
        icmp_ok = icmp_timestamp(ip, timeout, ts_attempts)
        if not icmp_ok:
            with print_lock:
                logger.warning(f"{ip} | FAIL | reason=No ICMP Timestamp reply")
            return None, "No ICMP Timestamp reply"
        http_ok = check_http_port(ip, http_port, timeout)
        if require_http and not http_ok:
            with print_lock:
                logger.warning(f"{ip} | FAIL | reason=HTTP port {http_port} unreachable")
            return None, "HTTP port unreachable"
        with print_lock:
            logger.info(f"{ip} | ALIVE | ping={rtt:.1f}ms | icmp_ts=Yes | http={'Yes' if http_ok else 'No'}")
        return ip, "ALIVE"
    except Exception as e:
        with print_lock:
            logger.error(f"{ip} | ERROR | {e}")
        return None, "Error"

def expand_to_24(cidrs: list) -> list:
    """Expand CIDRs to /24 subnets."""
    subnets = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.prefixlen < 24:
                subnets.extend(str(s.with_prefixlen) for s in net.subnets(new_prefix=24))
            else:
                subnets.append(str(net.with_prefixlen))
        except ValueError:
            logger.warning(f"Invalid CIDR: {cidr}")
    return sorted(set(subnets), key=lambda x: ipaddress.ip_network(x).network_address)

def load_input(path: str, mode: str) -> list:
    """Load and validate input from file."""
    if not os.path.isfile(path):
        logger.error(f"Input file '{path}' not found.")
        sys.exit(1)
    with open(path) as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    if mode == 'list':
        valid_ips = []
        for line in lines:
            try:
                ipaddress.ip_address(line)
                valid_ips.append(line)
            except ValueError:
                logger.warning(f"Invalid IP address: {line}")
        return valid_ips
    return lines

def chunks(lst: list, n: int):
    """Split list into chunks."""
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

def main():
    parser = argparse.ArgumentParser(
        description="Host detection tool using ICMP Echo, ICMP Timestamp, and optional HTTP checks.\n"
                    "Note: Use responsibly and with permission.",
    )
    parser.add_argument('-i', '--input', default='ranges.txt', help='Input CIDR or IP list')
    parser.add_argument('-o', '--output', default='alive_hosts.txt', help='Output file')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Timeout per probe (sec)')
    parser.add_argument('-r', '--rtt-threshold', type=float, default=2000.0, help='Max RTT (ms)')
    parser.add_argument('-p', '--http-port', type=int, default=80, help='HTTP port')
    parser.add_argument('--no-http', action='store_true', help='Disable HTTP check')
    parser.add_argument('-s', '--sample', action='store_true', help='Sample few hosts per subnet')
    parser.add_argument('-b', '--batch', type=int, default=16, help='CIDRs per batch')
    parser.add_argument('-w', '--workers', type=int, default=16, help='Worker threads')
    parser.add_argument('-m', '--mode', choices=['cidr', 'list'], default='cidr', help='Mode: cidr or list')
    parser.add_argument('--ping-attempts', type=int, default=4, help='Number of ping attempts')
    parser.add_argument('--ts-attempts', type=int, default=2, help='Number of ICMP TS attempts')
    args = parser.parse_args()

    logger.info("Starting host detection tool...")
    require_http = not args.no_http
    inputs = load_input(args.input, args.mode)
    if args.mode == 'cidr':
        logger.info(f"Expanding {len(inputs)} ranges → /24 subnets...")
        targets = expand_to_24(inputs)
    else:
        logger.info(f"Loading {len(inputs)} individual IPs...")
        targets = inputs
    logger.info(f"Targets: {len(targets)} | mode={args.mode} | HTTP required={'Yes' if require_http else 'No'} | RTT<th={args.rtt_threshold}ms")

    # Truncate the output file at the start
    with open(args.output, 'w') as out_f:
        pass  # This will truncate the file

    stats = {"Not Pingable": 0, "RTT too high": 0, "No ICMP Timestamp reply": 0, "HTTP port unreachable": 0, "ALIVE": 0, "Error": 0}
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        for batch in chunks(targets, args.batch):
            if stop_scanning:
                break
            batch_futures = []
            if args.mode == 'cidr':
                for cidr in batch:
                    net = ipaddress.ip_network(cidr, strict=False)
                    for ip in sample_hosts(net.hosts(), args.sample):
                        future = executor.submit(
                            scan_host, str(ip), args.timeout, args.rtt_threshold, require_http,
                            args.http_port, args.ping_attempts, args.ts_attempts)
                        batch_futures.append(future)
            else:  # list mode
                for ip in batch:
                    future = executor.submit(
                        scan_host, ip, args.timeout, args.rtt_threshold, require_http,
                        args.http_port, args.ping_attempts, args.ts_attempts)
                    batch_futures.append(future)
            
            batch_alive = []
            for fut in as_completed(batch_futures):
                if stop_scanning:
                    break
                res, reason = fut.result()
                if res:
                    batch_alive.append(res)
                stats[reason] += 1
            
            # Write batch_alive to file
            with open(args.output, 'a') as out_f:
                for ip in sorted(batch_alive):
                    out_f.write(ip + "\n")
            
            with print_lock:
                logger.info(f"Batch completed: {len(batch_alive)} alive hosts saved.")
            
            if stop_scanning:
                break

    logger.info(f"\nDone. Results: {args.output}")
    logger.info(f"Statistics: {stats}")

if __name__ == '__main__':
    main()
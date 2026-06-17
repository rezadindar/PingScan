import argparse
import ipaddress
import os
import platform
import signal
import subprocess
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Global flag for graceful shutdown
stop_scanning = False

def signal_handler(sig, frame):
    global stop_scanning
    print("\n[i] Ctrl+C received. Stopping...")
    stop_scanning = True

signal.signal(signal.SIGINT, signal_handler)

def last_hop(ip, timeout=2):
    """
    Use tracert/traceroute to return the last hop IP, or None if unreachable.
    """
    system = platform.system().lower()
    try:
        if 'windows' in system:
            cmd = ['tracert', '-d', '-h', '30', '-w', str(int(timeout * 1000)), ip]
            lines = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True).splitlines()[2:]
        else:
            cmd = ['traceroute', '-n', '-m', '30', '-w', str(timeout), ip]
            lines = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True).splitlines()[1:]
    except subprocess.CalledProcessError:
        return None
    # parse hops
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
    """
    Scan /24: reachable if last hop matches the IP.
    """
    global stop_scanning
    if stop_scanning:
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
        if stop_scanning:
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
    subs=[]
    for cidr in cidrs:
        try:
            net=ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.prefixlen<24:
            subs.extend([s.with_prefixlen for s in net.subnets(new_prefix=24)])
        elif net.prefixlen==24:
            subs.append(net.with_prefixlen)
        else:
            subs.append(net.supernet(new_prefix=24).with_prefixlen)
    return sorted(set(subs), key=lambda x: ipaddress.ip_network(x).network_address)


def chunks(lst,n):
    for i in range(0,len(lst),n):
        yield lst[i:i+n]


def main():
    parser = argparse.ArgumentParser(description='Traceroute scan: only mark if final hop equals target IP.')
    parser.add_argument('-i','--input',default='ranges.txt')
    parser.add_argument('-o','--output',default='reachable_hosts.txt')
    parser.add_argument('-t','--threads',type=int,default=128)
    parser.add_argument('-b','--batch',type=int,default=8)
    parser.add_argument('-w','--timeout',type=int,default=1)
    parser.add_argument('-s','--sample',action='store_true')
    parser.add_argument('-q','--quiet',action='store_true')
    args=parser.parse_args()

    cidrs=load_ranges(args.input)
    if not cidrs:
        print("[!] No valid CIDRs.")
        return
    subnets=expand_to_24(cidrs)
    if not args.quiet:
        print(f"[i] {len(cidrs)} ranges → {len(subnets)} /24 subnets | sample={'ON' if args.sample else 'OFF'}")
    results=set()
    with open(args.output,'w') as out_f:
        for idx,batch in enumerate(chunks(subnets,args.batch),1):
            if stop_scanning:
                break
            if not args.quiet:
                total=len(subnets)
                start=(idx-1)*args.batch+1
                end=min(idx*args.batch,total)
                print(f"\n[i] Batch {idx}: subnets {start}-{end} of {total}")
            with ThreadPoolExecutor(max_workers=args.threads) as ex:
                futures={ex.submit(scan_cidr,cidr,args.timeout,args.quiet,args.sample,out_f): cidr for cidr in batch}
                for fut in as_completed(futures):
                    if stop_scanning:
                        break
                    results.update(fut.result())
    print(f"\n✅ Scan complete. {len(results)} reachable hosts saved to '{args.output}'")

if __name__=='__main__':
    main()

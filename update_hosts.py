import argparse
import ipaddress
import sys
import requests


def load_ips(path):
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] File not found: {path}")
        sys.exit(1)


def pick_ips_from_diverse_ranges(ips, count=10):
    """Pick one random IP from each unique /24 range, up to `count` ranges (random order)."""
    import random
    ranges = {}
    for ip in ips:
        try:
            net = str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
            ranges.setdefault(net, []).append(ip)
        except ValueError:
            continue
    # shuffle range keys so we don't always pick the same ranges
    keys = list(ranges.keys())
    random.shuffle(keys)
    selected = [random.choice(ranges[k]) for k in keys[:count]]
    random.shuffle(selected)
    return selected


def get_all_hosts(base_url, token):
    url = f"{base_url}/api/hosts"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()["response"]


def update_host_address(base_url, token, host, address_str):
    url = f"{base_url}/api/hosts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
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
    r = requests.patch(url, json=payload, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()["response"]


def main():
    parser = argparse.ArgumentParser(
        description="Update Remnawave host addresses from scan results."
    )
    parser.add_argument("-i", "--input", default="reachable_hosts.txt",
                        help="Scanned IPs file (default: reachable_hosts.txt)")
    parser.add_argument("-u", "--url", required=True,
                        help="Remnawave panel base URL (e.g. https://panel.example.com)")
    parser.add_argument("-t", "--token", required=True,
                        help="Bearer token for authentication")
    parser.add_argument("-n", "--count", type=int, default=10,
                        help="Number of IPs to pick from different ranges (default: 10)")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")

    print(f"[i] Loading IPs from '{args.input}'...")
    ips = load_ips(args.input)
    if not ips:
        print("[!] No IPs found in input file.")
        sys.exit(1)
    print(f"[i] {len(ips)} IPs loaded.")

    selected = pick_ips_from_diverse_ranges(ips, args.count)
    if not selected:
        print("[!] Could not select IPs from diverse ranges.")
        sys.exit(1)

    address_str = ",".join(selected)
    print(f"[i] Selected {len(selected)} IPs from different /24 ranges:")
    print(f"    {address_str}\n")

    print("[i] Fetching hosts from Remnawave...")
    hosts = get_all_hosts(base_url, args.token)
    print(f"[i] {len(hosts)} host(s) found.\n")

    for host in hosts:
        uuid = host["uuid"]
        remark = host.get("remark") or uuid
        try:
            update_host_address(base_url, args.token, host, address_str)
            print(f"[+] Updated: {remark}")
        except requests.HTTPError as e:
            print(f"[!] Failed to update '{remark}': {e.response.status_code} {e.response.text}")
        except Exception as e:
            print(f"[!] Error updating '{remark}': {e}")

    print(f"\n✅ Done. {len(hosts)} host(s) updated.")


if __name__ == "__main__":
    main()

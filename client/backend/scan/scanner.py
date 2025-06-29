#!/usr/bin/env python3
from network import (
    get_default_ip, get_interface_by_ip, get_gateway, get_dns_servers,
    get_dhcp_server_systemd, scan_network, scan_with_nmap
)
import json, time
from pathlib import Path

# ── SCAN COMPLET ──────────────────────────────────────────────
def run_scan() -> dict:
    ip_local = get_default_ip()
    iface    = get_interface_by_ip(ip_local)

    hosts_up = scan_network(ip_local + "/24", iface)
    nmap_res = scan_with_nmap(hosts_up)

    return {
        "timestamp": int(time.time()),
        "network": {
            "ip": ip_local,
            "interface": iface,
            "gateway": get_gateway(),
            "dns": get_dns_servers(),
            "dhcp": get_dhcp_server_systemd(),
            "active_hosts": len(hosts_up),
        },
        "hosts": nmap_res,
    }

def save_report(data: dict) -> Path:
    Path("reports").mkdir(exist_ok=True)
    fn = Path("reports") / "scan.json"
    fn.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return fn

if __name__ == "__main__":          # test rapide
    report = run_scan()
    print(json.dumps(report, indent=2, ensure_ascii=False))
    save_report(report)

#!/usr/bin/env python3

from scapy.all import *
import os
import sys

NETWORK = "10.0.0.0/24"
TIMEOUT = 1

# Common services to probe
SERVICE_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-ALT"
}


def arp_scan(network):
    print(f"[+] ARP scanning {network}")

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=2, verbose=False, iface="eth0")

    hosts = []
    for _, reply in answered:
        hosts.append({
            "ip": reply.psrc,
            "mac": reply.hwsrc
        })

    return hosts


def tcp_syn_scan(ip, port):
    syn = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(syn, timeout=TIMEOUT, verbose=False)

    if resp and resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN-ACK
            # Clean up
            rst = IP(dst=ip) / TCP(dport=port, flags="R")
            send(rst, verbose=False)
            return True

    return False


def discover_services(hosts):
    print("\n[+] Discovering services on detected hosts")

    for host in hosts:
        ip = host["ip"]
        services = []

        for port, name in SERVICE_PORTS.items():
            if tcp_syn_scan(ip, port):
                services.append(f"{name} ({port})")

        host["services"] = services

    return hosts


def main():
    if os.geteuid() != 0:
        print("[-] Run this script as root.")
        sys.exit(1)

    hosts = arp_scan(NETWORK)
    hosts = discover_services(hosts)

    print("\n[+] Network service map:\n")

    for host in hosts:
        print(f"Host {host['ip']}  [{host['mac']}]")

        if host["services"]:
            for svc in host["services"]:
                print(f"    - {svc}")
        else:
            print("    - No known services detected")

        print()


if __name__ == "__main__":
    main()

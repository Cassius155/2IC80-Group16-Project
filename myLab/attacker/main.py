import scapy
from discovery import arp_scan, discover_services

NETWORK = "10.0.0.0/24"

if __name__ == "__main__":
    print("[*] Starting network discovery and service enumeration")
    hosts = arp_scan(NETWORK)
    services = discover_services(hosts)
    for host in services:
        print(f"Host: {host['ip']} - Services: {', '.join(host['services']) if host['services'] else 'None'}")
        
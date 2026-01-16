#!/usr/bin/env python3
"""
Network Discovery for MITM Attacks

Performs ARP scanning and port scanning to identify active hosts,
their services, and classify them by role (gateway, DNS, web server, victims).
"""

from scapy.all import *
import os
import sys
import socket
import struct
import netifaces


# Service fingerprints for host classification
SERVICE_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT"
}


def get_local_ip_and_network(interface="eth0"):
    """
    Get the attacker's IP address and network range.
    
    Returns:
        tuple: (ip_address, network_cidr, netmask)
    """
    try:
        addrs = netifaces.ifaddresses(interface)
        ipv4_info = addrs.get(netifaces.AF_INET)
        
        if not ipv4_info:
            raise ValueError(f"No IPv4 address found on {interface}")
        
        ip = ipv4_info[0]['addr']
        netmask = ipv4_info[0]['netmask']
        
        # Calculate network address
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        network_int = ip_int & mask_int
        network_addr = socket.inet_ntoa(struct.pack("!I", network_int))
        
        # Calculate CIDR prefix
        cidr = bin(mask_int).count('1')
        network_cidr = f"{network_addr}/{cidr}"
        
        return ip, network_cidr, netmask
        
    except Exception as e:
        print(f"[!] ERROR: Failed to detect network configuration on interface {interface}")
        print(f"[!] Details: {e}")
        print(f"[!] Make sure the interface exists and has an IPv4 address assigned.")
        print(f"[!] Available interfaces: {netifaces.interfaces()}")
        return None, None, None


def get_default_gateway():
    """
    Detect the default gateway IP address.
    
    Returns:
        str: Gateway IP address or None if not found
    """
    try:
        # Method 1: Use netifaces
        gws = netifaces.gateways()
        default_gw = gws.get('default')
        if default_gw and netifaces.AF_INET in default_gw:
            return default_gw[netifaces.AF_INET][0]
    except Exception:
        pass
    
    try:
        # Method 2: Parse /proc/net/route
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:  # skip header
                parts = line.strip().split()
                if len(parts) > 2:
                    destination = parts[1]
                    gateway = parts[2]
                    flags = int(parts[3], 16)
                    
                    # Check for default route (destination 00000000) with gateway flag
                    if destination == '00000000' and (flags & 2):
                        gw_int = int(gateway, 16)
                        return socket.inet_ntoa(struct.pack("<L", gw_int))
    except Exception:
        pass
    
    return None


def arp_scan(network, interface="eth0", timeout=3):
    """
    Perform ARP scan to discover active hosts on the network.
    
    Args:
        network (str): Network in CIDR notation (e.g., "10.0.0.0/24")
        interface (str): Network interface to use
        timeout (int): Scan timeout in seconds
    
    Returns:
        list: List of dicts with 'ip' and 'mac' keys
    """
    print(f"[*] Scanning network: {network}")
    print(f"[*] Using interface: {interface}")
    
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=timeout, verbose=False, iface=interface)
    
    hosts = []
    for _, reply in answered:
        hosts.append({
            "ip": reply.psrc,
            "mac": reply.hwsrc,
            "services": [],
            "role": "unknown"
        })
    
    print(f"[+] Found {len(hosts)} active hosts")
    return hosts


def tcp_syn_scan(ip, port, timeout=1):
    """
    Perform TCP SYN scan on a specific port.
    
    Args:
        ip (str): Target IP address
        port (int): Target port
        timeout (int): Scan timeout
    
    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        syn = IP(dst=ip) / TCP(dport=port, flags="S", sport=RandShort())
        resp = sr1(syn, timeout=timeout, verbose=False)
        
        if resp and resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN-ACK
                # Send RST to close connection gracefully
                rst = IP(dst=ip) / TCP(dport=port, flags="R", sport=resp[TCP].dport)
                send(rst, verbose=False)
                return True
        
        return False
    except Exception:
        return False


def discover_services(hosts, verbose=True):
    """
    Discover services running on each host via port scanning.
    
    Args:
        hosts (list): List of host dictionaries
        verbose (bool): Print progress messages
    
    Returns:
        list: Updated hosts list with service information
    """
    if verbose:
        print("\n[*] Discovering services on detected hosts...")
    
    for idx, host in enumerate(hosts):
        ip = host["ip"]
        if verbose:
            print(f"[*] Scanning {ip} ({idx + 1}/{len(hosts)})...", end="\r")
        
        open_ports = {}
        for port, name in SERVICE_PORTS.items():
            if tcp_syn_scan(ip, port):
                open_ports[port] = name
        
        host["services"] = open_ports
    
    if verbose:
        print(" " * 60, end="\r")  # clear progress line
        print("[+] Service discovery complete")
    
    return hosts


def classify_hosts(hosts, gateway_ip, attacker_ip):
    """
    Classify hosts based on their services and network position.
    
    Args:
        hosts (list): List of host dictionaries with service info
        gateway_ip (str): Known gateway IP
        attacker_ip (str): Attacker's own IP
    
    Returns:
        dict: Classified hosts by role
    """
    classified = {
        "gateway": None,
        "dns_servers": [],
        "web_servers": [],
        "victims": [],
        "attacker": None
    }
    
    for host in hosts:
        ip = host["ip"]
        services = host["services"]
        
        # Skip the attacker's own IP
        if ip == attacker_ip:
            host["role"] = "attacker"
            classified["attacker"] = host
            continue
        
        # Identify gateway
        if ip == gateway_ip:
            host["role"] = "gateway"
            classified["gateway"] = host
            continue
        
        # Identify DNS server (port 53 open)
        if 53 in services:
            host["role"] = "dns_server"
            classified["dns_servers"].append(host)
            continue
        
        # Identify web server (port 80 or 443 open)
        if 80 in services or 443 in services:
            host["role"] = "web_server"
            classified["web_servers"].append(host)
            continue
        
        # All other hosts are potential victims
        host["role"] = "victim"
        classified["victims"].append(host)
    
    return classified


def print_discovery_results(classified, attacker_ip, gateway_ip, network):
    """
    Print a comprehensive, formatted report of discovered hosts.
    
    Args:
        classified (dict): Classified hosts dictionary
        attacker_ip (str): Attacker's IP
        gateway_ip (str): Gateway IP
        network (str): Network CIDR
    """
    print("\n" + "=" * 70)
    print(" NETWORK RECONNAISSANCE REPORT")
    print("=" * 70)
    print(f"\nNetwork: {network}")
    print(f"Attacker IP: {attacker_ip}")
    print(f"Gateway IP: {gateway_ip}")
    print("\n" + "-" * 70)
    
    # Attacker
    if classified["attacker"]:
        host = classified["attacker"]
        print(f"\n[ATTACKER] {host['ip']} ({host['mac']})")
        print("  └─ This machine")
    
    # Gateway
    if classified["gateway"]:
        host = classified["gateway"]
        print(f"\n[GATEWAY] {host['ip']} ({host['mac']})")
        if host["services"]:
            for port, service in host["services"].items():
                print(f"  ├─ {service} (port {port})")
        print(f"  └─ Default gateway")
    
    # DNS Servers
    if classified["dns_servers"]:
        print("\n[DNS SERVERS]")
        for host in classified["dns_servers"]:
            print(f"  • {host['ip']} ({host['mac']})")
            for port, service in host["services"].items():
                print(f"    ├─ {service} (port {port})")
    
    # Web Servers
    if classified["web_servers"]:
        print("\n[WEB SERVERS]")
        for host in classified["web_servers"]:
            print(f"  • {host['ip']} ({host['mac']})")
            for port, service in host["services"].items():
                print(f"    ├─ {service} (port {port})")
    
    # Victims
    if classified["victims"]:
        print("\n[POTENTIAL VICTIMS]")
        for host in classified["victims"]:
            print(f"  • {host['ip']} ({host['mac']})")
            if host["services"]:
                for port, service in host["services"].items():
                    print(f"    ├─ {service} (port {port})")
            else:
                print(f"    └─ No services detected")
    
    print("\n" + "=" * 70)


def perform_full_discovery(interface="eth0", verbose=True):
    """
    Perform complete network discovery and return classified results.
    
    Args:
        interface (str): Network interface to use
        verbose (bool): Print detailed output
    
    Returns:
        dict: Discovery results with keys:
            - attacker_ip
            - gateway_ip
            - network
            - classified (hosts organized by role)
            - all_hosts (raw host list)
    """
    if os.geteuid() != 0:
        print("[!] ERROR: This script requires root privileges")
        print("[!] Please run with sudo")
        sys.exit(1)
    
    # Step 1: Detect local network configuration
    if verbose:
        print("\n[*] Step 1: Detecting network configuration...")
    
    attacker_ip, network, netmask = get_local_ip_and_network(interface)
    gateway_ip = get_default_gateway()
    
    if verbose:
        print(f"[+] Attacker IP: {attacker_ip}")
        print(f"[+] Network: {network}")
        print(f"[+] Gateway: {gateway_ip}")
    
    # Step 2: ARP scan for active hosts
    if verbose:
        print(f"\n[*] Step 2: Scanning for active hosts...")
    
    hosts = arp_scan(network, interface=interface)
    
    # Step 3: Service discovery
    if verbose:
        print(f"\n[*] Step 3: Port scanning for service identification...")
    
    hosts = discover_services(hosts, verbose=verbose)
    
    # Step 4: Host classification
    if verbose:
        print(f"\n[*] Step 4: Classifying hosts by role...")
    
    classified = classify_hosts(hosts, gateway_ip, attacker_ip)
    
    # Step 5: Print results
    if verbose:
        print_discovery_results(classified, attacker_ip, gateway_ip, network)
    
    return {
        "attacker_ip": attacker_ip,
        "gateway_ip": gateway_ip,
        "network": network,
        "classified": classified,
        "all_hosts": hosts,
        "interface": interface
    }


def main():
    """Standalone execution mode."""
    if os.geteuid() != 0:
        print("[!] ERROR: This script requires root privileges")
        print("[!] Please run with: sudo python3 discovery.py")
        sys.exit(1)
    
    # Detect interface (default to eth0)
    interface = "eth0"
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    
    print("=" * 70)
    print(" MITM Attack Toolkit - Network Discovery")
    print("=" * 70)
    
    results = perform_full_discovery(interface=interface, verbose=True)
    
    print("\n[+] Discovery complete!")
    print("[*] Use these parameters for the MITM attack:")
    print(f"    --attacker-ip {results['attacker_ip']}")
    print(f"    --gateway {results['gateway_ip']}")
    print(f"    --iface {results['interface']}")
    
    if results['classified']['dns_servers']:
        dns_ip = results['classified']['dns_servers'][0]['ip']
        print(f"    --dns {dns_ip}")
    
    if results['classified']['victims']:
        victim_ip = results['classified']['victims'][0]['ip']
        print(f"    <victim_ip> {victim_ip}")
    
    print()


if __name__ == "__main__":
    main()

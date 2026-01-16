#!/usr/bin/env python3

import sys
import os
from discovery import arp_scan, discover_services
from arp_poisoning import setupArpSpoof

NETWORK = "10.0.0.0/24"

def greet_user():
    print("=" * 50)
    print(" Automated Network Analysis & Attack Framework ")
    print("=" * 50)
    print()
    print("This tool will:")
    print("  • Discover active hosts on the local network")
    print("  • Identify available services")
    print("  • Allow selection of an attack module")
    print()


def run_network_discovery():
    print("\n" *3)
    discovered_hosts = arp_scan(NETWORK)
    discovered_hosts = discover_services(discovered_hosts)
    print("\n[+] Network discovery complete.")
    print("[+] Discovered hosts:")
    for host in discovered_hosts:
        print(f"Host: {host['ip']} - Services: {', '.join(host['services']) if host['services'] else 'None'}")
        

    return discovered_hosts


def show_attack_menu():
    print("\n" *3)
    print("\nAvailable attacks:")
    print("  1) ARP poisoning (MITM)")
    print("  2) DNS spoofing")
    print("  3) SSL stripping / HTTPS MITM")
    print("  4) Exit")

    choice = input("\nSelect an attack to execute: ")
    return choice.strip()


def handle_attack_choice(choice):
    if choice == "1":
        print("\n[*] ARP spoofing selected.")
        print("[!] ARP spoofing module not implemented yet.")
    elif choice == "2":
        print("\n[*] DNS spoofing selected.")
        print("[!] DNS spoofing module not implemented yet.")
    elif choice == "3":
        print("\n[*] SSL stripping selected.")
        print("[!] SSL stripping module not implemented yet.")
    elif choice == "4":
        print("\n[*] Exiting tool.")
        sys.exit(0)
    else:
        print("\n[-] Invalid selection.")


def main():
    greet_user()

    input("Press ENTER to start network discovery...")
    run_network_discovery()

    while True:
        choice = show_attack_menu()
        handle_attack_choice(choice)


if __name__ == "__main__":
    main()

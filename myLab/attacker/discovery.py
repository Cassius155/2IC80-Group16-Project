from scapy.all import *

def detectMachines(startIP, endIP):
    #Detects active machines in the network
    activeIPs = []
    for ip in range(startIP, endIP):
        stringIP = "10.0.0." + str(ip)
        packet = IP(dst=stringIP)/ICMP()
        response = sr1(packet, timeout=1, verbose=0)
        if response:
            activeIPs.append(stringIP)
    return activeIPs

def detectWebServers(activeIPs):
    webServers = []
    for ip in activeIPs:
        try:
            syn = IP(dst=ip)/TCP(dport=[80, 443], flags='S')
        except socket.gaierror:
            print(f"Could not resolve {ip}")
            continue
        responses, no_responses = sr(syn, timeout=2, retry=1, verbose=0)
        for sent, received in responses:
            if received.haslayer(TCP) and received.getlayer(TCP).flags == 0x12:
                webServers.append(ip)
        
ips = detectMachines(1, 10)
for ip in ips:
    print(f"Active IP found: {ip}")
webServers = detectWebServers(ips)
for server in webServers:
    print(f"Web server found at: {server}")
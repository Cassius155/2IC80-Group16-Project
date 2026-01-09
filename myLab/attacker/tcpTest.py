
from scapy.all import *

def tcp_scan(ip="10.0.0.1", ports=[443]):
    try:
        syn = IP(dst=ip) / TCP(dport=ports, flags="S")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))

    ans, unans = sr(syn, timeout=2, retry=1)
    result = []

    for sent, received in ans:
        if received[TCP].flags == "SA":
            result.append(received[TCP].sport)

    return result

if __name__ == "__main__":
    result = tcp_scan()
    print(result)


# 2IC80-Group16-Project

MITM toolkit for the 2IC80 project. It performs ARP poisoning to sit between victim and gateway (and optionally the DNS server), then spoofs DNS replies (NFQUEUE if available, sniff-and-reply fallback otherwise). 

Primary entrypoint is `exploit.py`, but individual modules can be run on their own. SSL stripping is still to be implemented.

## What it does
- ARP poisoning: continuously forges ARP replies so the victim routes traffic (and DNS queries, if `--dns` is used) to the attacker.
- DNS spoofing: intercepts DNS queries and answers with an attacker-chosen IP; in sniff-mode it drops forwarded UDP/53 to beat the legitimate DNS reply.

## Lab setup (quick)
- From the repo root, change to the `myLab` directory and start the Kathara lab. Example:

```bash
# from the repository root
cd myLab

# start the lab (will take ~5 minutes for all the machines to set up)
kathara lstart

# if you need a full restart, instead do:
# kathara lclean && kathara lstart
```

- Attach to the `attacker` container to run the commands below; victim is `pc2`, gateway `web1`, DNS `dns1` per the lab defaults.
- Ensure you run as root inside the attacker container.


## Usage (attacker container)

General-purpose (replace placeholders):

```bash
# general template (replace the angled placeholders):
python3 attacker/exploit.py <target_ip> <gateway_ip> --dns <dns_ip> --domain <fqdn> --rdata <redirect_ip> --iface <iface> --delay <seconds>
```

Flag mapping for the template above:
- `<target_ip>`: victim IP address (positional)
- `<gateway_ip>`: gateway IP address (positional)
- `--dns <dns_ip>`: (optional) DNS server IP to poison toward the victim so DNS queries reach the attacker
- `--domain <fqdn>`: domain to spoof (include trailing dot for exact match)
- `--rdata <redirect_ip>`: IP address to return in spoofed DNS replies
- `--iface <iface>`: network interface to use for sniffing/sending (e.g., `eth0`)
- `--delay <seconds>`: seconds to wait after ARP poisoning starts before launching DNS spoofing (optional)

Kathara lab example (recommended):

```bash
# Fully automated attack (recommended): ARP -> brief delay -> DNS
python3 exploit.py 10.0.0.4 10.0.0.1 --dns 10.0.0.2 --domain web1.mylab.test. --rdata 10.0.0.3 --iface eth0

# or run modules separately (optional)
python3 arp_poisoning.py 10.0.0.4 10.0.0.1 --dns 10.0.0.2
python3 dns_spoofing.py --domain web1.mylab.test. --rdata 10.0.0.3 --iface eth0
```

Notes
- Sniff-mode requires the victim to send DNS queries to the attacker (use `--dns` ARP poisoning so the victim’s DNS traffic hits you at L2).
- In sniff-mode the tool inserts and later removes DROP rules on UDP/53 (FORWARD) to prevent the real DNS reply from winning the race.
- Press Ctrl+C to clean up (ARP restore + iptables cleanup).
- `web1` serves HTTPS only; `curl -k https://web1.mylab.test` to ignore the self-signed cert, or host separate HTTP content if needed.

## Prerequisites (outside Kathara lab environment)
If you plan to run the tools outside the provided Kathara lab, install the following on a Debian/Ubuntu host. The Kathara startup scripts already install these inside the lab, but outside the lab you'll need them manually.

```bash
# update
sudo apt update

# install system packages
sudo apt install -y python3 python3-pip python3-dev build-essential libpcap-dev libnetfilter-queue-dev libnfnetlink-dev iptables iproute2

# install Python packages
sudo pip3 install scapy NetfilterQueue
```

### Important notes:
- NFQUEUE requires kernel support (module `nfnetlink_queue`). If the kernel lacks NFQUEUE support, `dns_spoofing.py` will automatically fall back to sniff-mode.
- You must run the scripts as root (or via `sudo`) because they use raw sockets and modify iptables.
- Enable IP forwarding if not already enabled:

```bash
# temporary (until reboot)
sudo sysctl -w net.ipv4.ip_forward=1

# persistent (Debian/Ubuntu)
sudo sed -i 's/^#\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sudo sysctl -p
```

- If you don't have NFQUEUE available, the tool's sniff fallback will add DROP rules on UDP/53 and attempt to reply directly (you still need to ensure victims send DNS to the attacker, e.g., by ARP poisoning `--dns`).

### Other operating systems / distributions (non-Debian)
Below are example install commands for other popular distributions. Package names may vary slightly by release; use your distribution's package manager to find the closest package names if a command fails.

macOS (Homebrew):
```bash
# install Homebrew first if needed: https://brew.sh/
brew install python3 libpcap
# note: NetfilterQueue / nfnetlink is Linux-specific; NFQUEUE will not be available on macOS.
sudo pip3 install scapy
```

Arch Linux:
```bash
sudo pacman -Syu --noconfirm python python-pip base-devel libpcap libnetfilter_queue iptables
```

Notes:
- NFQUEUE relies on Linux kernel support (`nfnetlink_queue`). If your kernel lacks that module, the spoofer will fall back to sniff-mode.
- On non-Debian systems you still need to install the Python `NetfilterQueue` package if you want NFQUEUE support (pip3 install NetfilterQueue) and the appropriate development headers (`libnetfilter_queue-devel` / `libnetfilter-queue` packages) to build it.
- macOS generally cannot provide NFQUEUE functionality; use Linux for full NFQUEUE support.
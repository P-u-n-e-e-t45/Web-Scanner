#!/usr/bin/env python3
"""Automated Web Security Scanner (single-file version).

Audits a website for missing/weak HTTP security headers and CORS
misconfigurations, and prints a severity-ranked report.

Usage:
    python web_scanner.py https://your-own-site.com --authorized
    python web_scanner.py -f targets.txt --authorized --format json -o report.json
    python web_scanner.py --demo        # start an intentionally weak local test server
    python web_scanner.py --selftest    # run built-in unit tests

Only scan sites you own or have written permission to test.
"""
import argparse
import csv
import io
import json
import re
import sys
from urllib.parse import urlparse

import requests

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

REQUIRED_HEADERS = {
    "Strict-Transport-Security": ("MEDIUM", "Missing HSTS"),
    "Content-Security-Policy": ("MEDIUM", "Missing CSP"),
    "X-Content-Type-Options": ("LOW", "Missing X-Content-Type-Options"),
    "X-Frame-Options": ("LOW", "Missing clickjacking protection (X-Frame-Options or CSP frame-ancestors)"),
    "Referrer-Policy": ("LOW", "Missing Referrer-Policy"),
    "Permissions-Policy": ("INFO", "Missing Permissions-Policy"),
}


def finding(severity, check, message):
    return {"severity": severity, "check": check, "message": message}


# ---------- Header checks ----------
def check_headers(headers):
    findings = []
    h = {k.lower(): v for k, v in headers.items()}

    for name, (severity, message) in REQUIRED_HEADERS.items():
        if name.lower() not in h:
            if name == "X-Frame-Options" and "frame-ancestors" in h.get("content-security-policy", ""):
                continue
            findings.append(finding(severity, "header", message))

    hsts = h.get("strict-transport-security")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts, re.I)
        if not m or int(m.group(1)) < 15552000:
            findings.append(finding("LOW", "header", "HSTS max-age is below 180 days"))

    csp = h.get("content-security-policy")
    if csp:
        for bad in ("unsafe-inline", "unsafe-eval"):
            if bad in csp:
                findings.append(finding("MEDIUM", "header", f"CSP allows '{bad}'"))

    xcto = h.get("x-content-type-options")
    if xcto and xcto.strip().lower() != "nosniff":
        findings.append(finding("LOW", "header", "X-Content-Type-Options should be 'nosniff'"))
    return findings


# ---------- CORS checks ----------
def probe_origin(url, origin, timeout):
    r = requests.get(url, headers={"Origin": origin}, timeout=timeout)
    acao = r.headers.get("Access-Control-Allow-Origin")
    creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    return acao, creds


def check_cors(url, timeout=10):
    host = urlparse(url).hostname or ""
    probes = {
        "arbitrary origin": "https://evil.example",
        "null origin": "null",
        "look-alike domain": f"https://{host}.evil.example",
    }
    findings = []
    for label, origin in probes.items():
        acao, creds = probe_origin(url, origin, timeout)
        if acao == origin:
            severity = "HIGH" if creds else "MEDIUM"
            findings.append(finding(
                severity, "cors",
                f"Reflects {label} ({origin}); credentials allowed: {creds}"))
        elif acao == "*":
            findings.append(finding("LOW", "cors", "Wildcard Access-Control-Allow-Origin"))
            break
    return findings


# ---------- Scanning ----------
def scan(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout)
        findings = check_headers(r.headers) + check_cors(url, timeout)
        return {"url": url, "status": r.status_code, "findings": findings}
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc), "findings": []}


# ---------- Reporting ----------
def _sorted(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))


def to_text(results):
    lines = []
    for res in results:
        lines.append(f"\n== {res['url']} ==")
        if res.get("error"):
            lines.append(f"  ERROR: {res['error']}")
            continue
        if not res["findings"]:
            lines.append("  No findings.")
        for f in _sorted(res["findings"]):
            lines.append(f"  [{f['severity']}] ({f['check']}) {f['message']}")
    return "\n".join(lines)


def to_json(results):
    return json.dumps(results, indent=2)


def to_csv(results):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["url", "severity", "check", "message"])
    for res in results:
        for f in _sorted(res.get("findings", [])):
            w.writerow([res["url"], f["severity"], f["check"], f["message"]])
    return buf.getvalue()


FORMATS = {"text": to_text, "json": to_json, "csv": to_csv}


# ---------- Demo server (intentionally misconfigured, for testing) ----------
def run_demo_server(port=8000):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            origin = self.headers.get("Origin")
            if origin:  # BAD: reflects any origin and allows credentials
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Security-Policy", "script-src 'unsafe-inline'")
            self.send_header("Strict-Transport-Security", "max-age=100")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    print(f"Vulnerable demo server on http://127.0.0.1:{port} (Ctrl+C to stop)")
    try:
        ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


# ---------- Built-in unit tests ----------
def run_selftest():
    import unittest

    def msgs(headers):
        return [f["message"] for f in check_headers(headers)]

    class HeaderTests(unittest.TestCase):
        def test_missing_hsts(self):
            self.assertIn("Missing HSTS", msgs({}))

        def test_weak_hsts(self):
            self.assertIn("HSTS max-age is below 180 days",
                          msgs({"Strict-Transport-Security": "max-age=100"}))

        def test_csp_unsafe_inline(self):
            self.assertIn("CSP allows 'unsafe-inline'",
                          msgs({"Content-Security-Policy": "script-src 'unsafe-inline'"}))

        def test_frame_ancestors_ok(self):
            m = msgs({"Content-Security-Policy": "frame-ancestors 'none'"})
            self.assertFalse(any("clickjacking" in x for x in m))

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(HeaderTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


# ---------- CLI ----------
def main(argv=None):
    p = argparse.ArgumentParser(description="Security header and CORS scanner")
    p.add_argument("urls", nargs="*", help="Target URLs")
    p.add_argument("-f", "--file", help="File with one URL per line")
    p.add_argument("--format", choices=FORMATS, default="text")
    p.add_argument("-o", "--output", help="Write report to this file")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--authorized", action="store_true",
                   help="Confirm you own the targets or have written permission to test them")
    p.add_argument("--demo", action="store_true", help="Run the intentionally weak local test server")
    p.add_argument("--selftest", action="store_true", help="Run built-in unit tests")
    args = p.parse_args(argv)

    if args.selftest:
        return run_selftest()
    if args.demo:
        run_demo_server()
        return 0

    if not args.authorized:
        p.error("--authorized is required: only scan sites you own or have permission to test")

    urls = list(args.urls)
    if args.file:
        with open(args.file) as fh:
            urls += [line.strip() for line in fh if line.strip()]
    if not urls:
        p.error("provide at least one URL or --file")

    report = FORMATS[args.format]([scan(u, args.timeout) for u in urls])
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report)
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())

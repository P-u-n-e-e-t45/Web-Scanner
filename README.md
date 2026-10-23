# Web Security Scanner

A Python CLI that audits websites for missing or weak security headers and common CORS misconfigurations, then reports findings ranked by severity.

> **Use only on sites you own or have written permission to test.**
> The CLI requires the `--authorized` flag to confirm this.

## Features
- Security header audit: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- Value checks, not just presence (HSTS `max-age`, CSP `unsafe-inline`/`unsafe-eval`, `nosniff`)
- CORS probes: reflected origin, `null` origin, wildcard, credentials combined with permissive origin, look-alike domain
- Severity levels: HIGH / MEDIUM / LOW / INFO
- Output as text, JSON or CSV
- Multiple targets in one run

## Install
```bash
git clone https://github.com/<your-username>/web-scanner.git
cd web-scanner
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
python -m scanner https://example.com --authorized
python -m scanner https://a.com https://b.com --authorized --format json -o report.json
python -m scanner -f targets.txt --authorized --format csv -o report.csv
```

## Project structure
```
scanner/
  headers.py   # security header checks
  cors.py      # CORS probes
  report.py    # text / JSON / CSV output
  cli.py       # argument parsing and orchestration
tests/         # pytest unit tests
```

## Run tests
```bash
pip install pytest && pytest
```

## Roadmap
- [ ] Async scanning (aiohttp)
- [ ] Cookie flag checks (Secure, HttpOnly, SameSite)
- [ ] HTML report
- [ ] GitHub Actions CI

## License
MIT

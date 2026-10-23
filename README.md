# PHP & CMS Security Scanner (MVP)

An authorization-gated, passive web technology and HTTP configuration scanner built using FastAPI. **This is not a confirmed PHP2Shell exploit detector or a complete CMS/CVE scanner.**

## Capabilities
- HTTPS homepage inspection, WordPress/Drupal/Joomla/Laravel/Bootstrap/jQuery indicators
- Response-header and visible error-disclosure checks
- JSON findings and PDF report
- HTTP Basic authentication and an exact-match domain allowlist

## Run locally

```bash
pip install -r requirements.txt
export SCANNER_USERNAME=admin
export SCANNER_PASSWORD='replace-with-long-random-password'
export SCANNER_ALLOWED_DOMAINS=example.com
uvicorn app:app --reload
```

Browse http://localhost:8000 and authenticate with your configured credentials. Only targets explicitly named in SCANNER_ALLOWED_DOMAINS can be scanned (comma-separated exact hostnames).

## Render hosting
Connect this GitHub repository to https://dashboard.render.com/blueprints and deploy its render.yaml Blueprint. Configure SCANNER_USERNAME, SCANNER_PASSWORD and SCANNER_ALLOWED_DOMAINS as secret environment variables. Do not commit passwords.

## Security and limitations
**Not for unrestricted public use.** HTTPS-only, disabled redirects, public-DNS validation, an explicit allowed-target list and Basic authentication reduce risk but do not eliminate it. Basic auth must only be used behind HTTPS. In particular, DNS rebinding is not completely mitigated because the validation resolution is not pinned to the outbound connection. Use egress firewall rules and DNS pinning before admitting untrusted users; use real ownership verification, audit logging, rate limits, SSO and persistent job storage for production. Reports are in memory and are lost on restart. Only the homepage is examined: no exploitation, directory scanning, package inventory, CVE matching, or verified detection of PHP web shells.

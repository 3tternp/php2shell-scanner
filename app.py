import asyncio
import html
import ipaddress
import os
import re
import secrets
import socket
import uuid
from datetime import datetime, timezone
from io import BytesIO
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

app = FastAPI(title="Authorized PHP and CMS Security Scanner", version="0.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["https://3tternp.github.io"], allow_methods=["GET","POST"], allow_headers=["Authorization","Content-Type"], allow_credentials=False)
results = {}
LIMIT = asyncio.Semaphore(2)

@app.middleware("http")
async def basic_auth(request: Request, call_next):
    # Browser CORS preflight carries no credentials. Let CORSMiddleware
    # validate the Origin and requested headers/method, rather than
    # responding with a Basic Auth challenge before the preflight.
    if request.method == "OPTIONS" and request.headers.get("origin"):
        return await call_next(request)
    if request.url.path == "/health":
        return await call_next(request)
    user = os.getenv("SCANNER_USERNAME", "")
    password = os.getenv("SCANNER_PASSWORD", "")
    if not user or not password:
        return Response("Scanner credentials are not configured.", status_code=503)
    auth = request.headers.get("authorization", "")
    valid = False
    if auth.startswith("Basic "):
        import base64
        try:
            candidate = base64.b64decode(auth[6:], validate=True).decode()
            u, p = candidate.split(":", 1)
            valid = secrets.compare_digest(u, user) and secrets.compare_digest(p, password)
        except (ValueError, UnicodeError):
            pass
    if not valid:
        return Response("Authentication required", status_code=401, headers={
            "WWW-Authenticate": 'Basic realm="Authorized Scanner"',
            "Cache-Control": "no-store"
        })
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/health")
def health():
    return {"status": "ok"}

class ScanInput(BaseModel):
    domain: str = Field(min_length=4, max_length=253)
    authorization_confirmed: bool

def validate_target(raw: str):
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname
    if (not host or parsed.username or parsed.password or parsed.port not in (None, 443)
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("Enter a domain without paths, credentials or custom ports")
    host = host.lower()
    if not re.fullmatch(r"(?=.{4,253}$)[a-z0-9-]+(?:\.[a-z0-9-]+)+", host):
        raise ValueError("Invalid domain")
    allowed = {x.strip().lower() for x in os.getenv("SCANNER_ALLOWED_DOMAINS", "").split(",") if x.strip()}
    if not allowed or host not in allowed:
        raise ValueError("Domain is not in SCANNER_ALLOWED_DOMAINS (exact hostname match required)")
    return "https://" + host, host

def validate_public_dns(host: str):
    addresses = {x[4][0] for x in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise ValueError("Domain must resolve only to public IP addresses")

def finding(title, severity, evidence, remediation):
    return {"title": title, "severity": severity, "evidence": evidence, "remediation": remediation}

async def run_scan(sid, base, host):
    async with LIMIT:
        r = results[sid]
        r["status"] = "running"
        try:
            await asyncio.to_thread(validate_public_dns, host)
            # Redirects and ambient proxy settings are disabled. Hostname allowlisting
            # limits who can be scanned. Pin DNS at the network layer before exposing
            # this MVP to untrusted administrative users.
            async with httpx.AsyncClient(
                timeout=12, follow_redirects=False, trust_env=False,
                headers={"User-Agent": "AuthorizedSecurityScanner/0.2"}
            ) as client:
                resp = await client.get(base + "/")
            body = resp.text[:300000]
            headers = resp.headers
            tech, findings = [], []
            if headers.get("server"):
                tech.append("Server: " + headers["server"][:100])
            if headers.get("x-powered-by"):
                tech.append("X-Powered-By: " + headers["x-powered-by"][:100])
                findings.append(finding("Technology disclosure", "Low", headers["x-powered-by"][:100], "Remove unnecessary technology disclosure headers."))
            patterns = {
                "WordPress": r"wp-content/|wp-includes/",
                "Drupal": r"Drupal.settings|/sites/default/|drupalSettings",
                "Joomla": r"/media/system/js/|com_content|Joomla!",
                "Laravel": r"laravel_session|csrf-token",
                "Bootstrap": r"bootstrap(?:\.min)?\.(?:css|js)",
                "jQuery": r"jquery(?:\.min)?\.js",
            }
            for name, pattern in patterns.items():
                if re.search(pattern, body, re.I):
                    tech.append(name)
            for key in ("content-security-policy", "strict-transport-security", "x-content-type-options", "referrer-policy"):
                if key not in headers:
                    findings.append(finding("Missing " + key, "Low", key + " header not present", "Configure the header according to application requirements."))
            if re.search(r"<title>\s*Index of /|<h1>Index of /", body, re.I):
                findings.append(finding("Possible directory listing", "Medium", "Directory index marker on homepage", "Disable directory listing."))
            if re.search(r"fatal error|uncaught exception|stack trace|php warning:", body, re.I):
                findings.append(finding("Possible application error disclosure", "Medium", "Error marker on homepage", "Disable production debug output."))
            r.update(status="completed", http_status=resp.status_code, technologies=tech,
                     findings=findings, completed_at=datetime.now(timezone.utc).isoformat(),
                     note="Passive homepage assessment only; does not confirm PHP2Shell exploitation, web shells, plugin versions or CVEs.")
        except Exception as exc:
            r.update(status="failed", error=str(exc)[:200])

@app.post("/api/scans")
async def start_scan(payload: ScanInput):
    if not payload.authorization_confirmed:
        raise HTTPException(400, "Authorization confirmation required")
    try:
        base, host = validate_target(payload.domain)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    sid = str(uuid.uuid4())
    results[sid] = {"id": sid, "domain": host, "status": "queued",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "findings": [], "technologies": []}
    asyncio.create_task(run_scan(sid, base, host))
    return results[sid]

@app.get("/api/scans/{sid}")
def get_scan(sid: str):
    if sid not in results:
        raise HTTPException(404, "Scan not found")
    return results[sid]

@app.get("/api/scans/{sid}/report.pdf")
def pdf_report(sid: str):
    if sid not in results:
        raise HTTPException(404, "Scan not found")
    r = results[sid]
    if r["status"] != "completed":
        raise HTTPException(409, "Scan is not completed")
    stream = BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [Paragraph("Authorized Web Security Assessment", styles["Title"]), Spacer(1, 18)]
    for key in ("domain", "started_at", "completed_at", "http_status", "note"):
        story.append(Paragraph("<b>" + key.replace("_", " ").title() + ":</b> " + html.escape(str(r.get(key, ""))), styles["BodyText"]))
        story.append(Spacer(1, 8))
    story.append(Paragraph("Observed Technologies", styles["Heading2"]))
    for t in r["technologies"]:
        story.append(Paragraph(html.escape(t), styles["BodyText"]))
    story.append(Paragraph("Findings", styles["Heading2"]))
    for f in r["findings"]:
        story.append(Paragraph(html.escape(f["severity"] + " — " + f["title"]), styles["Heading3"]))
        story.append(Paragraph("Evidence: " + html.escape(f["evidence"]), styles["BodyText"]))
        story.append(Paragraph("Remediation: " + html.escape(f["remediation"]), styles["BodyText"]))
    doc.build(story)
    stream.seek(0)
    return StreamingResponse(stream, media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="scan-' + sid + '.pdf"'})

@app.get("/", response_class=HTMLResponse)
def home():
    return """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PHP & CMS Security Scanner</title>
<style>body{font:16px system-ui;background:#0b1220;color:#e9f0fa;max-width:860px;margin:50px auto;padding:20px}main{background:#17243a;padding:30px;border-radius:16px}input[type=text]{width:95%;padding:13px;background:#0b1220;border:1px solid #55657c;color:white;border-radius:8px}button,a.btn{background:#38bdf8;border:0;border-radius:8px;padding:12px 20px;color:#07121e;font-weight:bold;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1220;padding:18px;border-radius:8px}small{color:#aebbd0}</style>
<main><h1>🛡️ PHP & CMS Security Scanner</h1><p>Authorized passive technology fingerprinting and security header assessment.</p>
<form id="scan"><label>Authorized domain</label><p><input id="domain" type="text" placeholder="example.com" required></p><p><label><input id="authorized" type="checkbox" required> I own this domain or have written assessment authorization.</label></p><button type="submit">Start assessment</button></form>
<p id="status"></p><pre id="output" hidden></pre><a id="pdf" class="btn" hidden>Download PDF report</a><p><small>MVP: no exploitation, CMS package enumeration, CVE verification, or PHP2Shell confirmation. Targets must be configured in SCANNER_ALLOWED_DOMAINS.</small></p></main>
<script>
const form=document.getElementById("scan"),statusEl=document.getElementById("status"),out=document.getElementById("output"),pdf=document.getElementById("pdf");
form.onsubmit=async e=>{e.preventDefault();out.hidden=true;pdf.hidden=true;statusEl.textContent="Submitting...";
try{let r=await fetch("/api/scans",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain:document.getElementById("domain").value,authorization_confirmed:document.getElementById("authorized").checked})});
let data=await r.json();if(!r.ok)throw Error(JSON.stringify(data));
for(let i=0;i<35;i++){await new Promise(resolve=>setTimeout(resolve,1000));let x=await fetch("/api/scans/"+data.id);data=await x.json();statusEl.textContent="Status: "+data.status;if(["completed","failed"].includes(data.status))break}
out.hidden=false;out.textContent=JSON.stringify(data,null,2);if(data.status==="completed"){pdf.href="/api/scans/"+data.id+"/report.pdf";pdf.hidden=false}
}catch(err){statusEl.textContent=err.message}};
</script></html>"""

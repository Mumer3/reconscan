#!/usr/bin/env python3
"""
Advanced Domain Recon & Network Mapping Tool
Real-world grade: wildcard detection, HTTP probing, TLS inspection,
port scanning, WAF/CDN fingerprinting, tech stack detection.
"""

import socket
import ssl
import dns.resolver
import requests
import whois
import csv
import json
import logging
import threading
import time
import re
import sys
import os
import random
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from colorama import init, Fore, Style
init(autoreset=True)

# ─────────────────────── CONFIG ───────────────────────
DOMAIN     = ""          # Set via CLI arg or prompt
WORDLIST   = "wordlists/subdomains.txt"
THREADS    = 25
TIMEOUT    = 5           # seconds per network call
MAX_RETRIES = 2
OUTPUT_DIR = "output"

# Ports to probe per live subdomain
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017]

# WAF / CDN fingerprint signatures (header → name)
WAF_SIGNATURES = {
    "cf-ray":              "Cloudflare",
    "x-sucuri-id":         "Sucuri",
    "x-akamai-transformed":"Akamai",
    "x-cache":             "CDN (generic)",
    "x-fastly-request-id": "Fastly",
    "x-amz-cf-id":         "AWS CloudFront",
    "x-azure-ref":         "Azure CDN",
    "x-cdn":               "CDN (generic)",
    "server: incapsula":   "Imperva Incapsula",
    "x-iinfo":             "Imperva Incapsula",
}

TECH_HEADERS = {
    "server":          "Server",
    "x-powered-by":   "X-Powered-By",
    "x-generator":    "Generator",
    "x-drupal-cache":  "Drupal",
    "x-wp-total":      "WordPress",
    "x-shopify-stage": "Shopify",
}

# ─────────────────────── LOGGING ───────────────────────
os.makedirs(OUTPUT_DIR, exist_ok=True)
log_path = os.path.join(OUTPUT_DIR, f"recon_{datetime.now():%Y%m%d_%H%M%S}.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("recon")

# Thread-safe result store
_lock = threading.Lock()
RESULTS = {
    "meta": {
        "tool": "Advanced Domain Recon Tool",
        "scan_time": datetime.now().isoformat(),
        "target": ""
    },
    "domain_info": {},
    "dns_records": {},
    "subdomains": []
}

# ─────────────────────── HELPERS ───────────────────────
def retry(fn, *args, attempts=MAX_RETRIES, delay=1.5, **kwargs):
    """Call fn with retries on exception."""
    for i in range(attempts):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            if i < attempts - 1:
                time.sleep(delay * (i + 1))
            else:
                return None

def safe_get(url, **kwargs):
    """HTTP GET with timeout, retries, and a realistic UA."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    }
    headers.update(kwargs.pop("headers", {}))
    return retry(
        requests.get,
        url,
        headers=headers,
        timeout=TIMEOUT,
        allow_redirects=True,
        verify=False,
        **kwargs
    )

# ─────────────────────── WILDCARD CHECK ───────────────────────
def detect_wildcard(domain):
    """
    Detect wildcard DNS. Returns the wildcard IP if found, else None.
    Real tools MUST do this to avoid thousands of false positives.
    """
    random_sub = f"wildcard-check-{random.randint(100000,999999)}.{domain}"
    ip = resolve_ip(random_sub)
    if ip:
        logger.warning(f"⚠  Wildcard DNS detected for *.{domain} → {ip}")
        logger.warning("   Subdomains resolving to this IP will be flagged as wildcard matches.")
    return ip

# ─────────────────────── IP / DNS ───────────────────────
def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def get_geo_ip(ip):
    """Use ipinfo.io for geolocation (free tier, no key needed)."""
    try:
        res = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=TIMEOUT,
            headers={"Accept": "application/json"}
        ).json()
        return {
            "ip":       ip,
            "city":     res.get("city"),
            "region":   res.get("region"),
            "country":  res.get("country"),
            "org":      res.get("org"),
            "location": res.get("loc"),
            "timezone": res.get("timezone"),
            "hostname": res.get("hostname"),
        }
    except Exception:
        return {"ip": ip}

def get_dns_records(hostname):
    """Fetch A, AAAA, CNAME, MX, NS, TXT, SOA records."""
    records = {}
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]:
        try:
            answers = dns.resolver.resolve(hostname, rtype, lifetime=TIMEOUT)
            records[rtype] = [r.to_text() for r in answers]
        except Exception:
            records[rtype] = []
    return records

# ─────────────────────── PORT SCAN ───────────────────────
def scan_ports(ip, ports=COMMON_PORTS):
    """TCP connect scan on common ports. Returns list of open ports."""
    open_ports = []
    def probe(port):
        try:
            with socket.create_connection((ip, port), timeout=1.5):
                open_ports.append(port)
        except Exception:
            pass
    with ThreadPoolExecutor(max_workers=20) as ex:
        ex.map(probe, ports)
    return sorted(open_ports)

# ─────────────────────── TLS INSPECTION ───────────────────────
def get_tls_info(hostname, port=443):
    """Extract certificate details: CN, SANs, issuer, validity."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=TIMEOUT),
            server_hostname=hostname
        ) as ssock:
            cert = ssock.getpeercert()
            if not cert:
                # get DER and parse manually
                return {"tls": True, "note": "No cert info returned"}
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            sans = [
                v for (t, v) in cert.get("subjectAltName", [])
                if t == "DNS"
            ]
            return {
                "tls":         True,
                "cn":          subject.get("commonName"),
                "org":         subject.get("organizationName"),
                "issuer_cn":   issuer.get("commonName"),
                "issuer_org":  issuer.get("organizationName"),
                "san_count":   len(sans),
                "sans_sample": sans[:10],
                "not_before":  cert.get("notBefore"),
                "not_after":   cert.get("notAfter"),
                "version":     ssock.version(),
                "cipher":      ssock.cipher()[0] if ssock.cipher() else None,
            }
    except ssl.SSLError as e:
        return {"tls": True, "ssl_error": str(e)}
    except Exception:
        return {"tls": False}

# ─────────────────────── HTTP PROBING ───────────────────────
def probe_http(hostname):
    """
    Try HTTPS then HTTP. Returns status code, title, redirect chain,
    WAF/CDN detection, and technology fingerprints.
    """
    result = {
        "http_status":  None,
        "https_status": None,
        "title":        None,
        "redirect_url": None,
        "waf_cdn":      [],
        "technologies": {},
        "server":       None,
        "x_powered_by": None,
    }

    def _probe(scheme):
        url = f"{scheme}://{hostname}"
        resp = safe_get(url)
        if not resp:
            return None, url
        return resp, resp.url  # final URL after redirects

    for scheme in ["https", "http"]:
        resp, final_url = _probe(scheme)
        if resp is None:
            continue

        key = f"{scheme}_status"
        result[key] = resp.status_code

        if final_url != f"{scheme}://{hostname}":
            result["redirect_url"] = final_url

        # Page title
        if result["title"] is None:
            m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            result["title"] = m.group(1).strip()[:120] if m else None

        # WAF / CDN detection
        lower_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        for sig, name in WAF_SIGNATURES.items():
            if ":" in sig:
                hdr, val = sig.split(": ", 1)
                if lower_headers.get(hdr, "").startswith(val):
                    result["waf_cdn"].append(name)
            elif sig in lower_headers:
                result["waf_cdn"].append(name)

        # Technology fingerprints
        for hdr, label in TECH_HEADERS.items():
            val = resp.headers.get(hdr)
            if val:
                result["technologies"][label] = val

        result["server"] = resp.headers.get("server")
        result["x_powered_by"] = resp.headers.get("x-powered-by")

        # Only need to probe one scheme for most metadata
        if resp.status_code < 500:
            break

    result["waf_cdn"] = list(set(result["waf_cdn"]))
    return result

# ─────────────────────── DOMAIN INFO ───────────────────────
def get_domain_info(domain):
    try:
        w = whois.whois(domain)
        def _str(v):
            if isinstance(v, list):
                return [str(x) for x in v]
            return str(v) if v else None
        return {
            "domain_name":      _str(w.domain_name),
            "registrar":        w.registrar,
            "registrar_url":    w.registrar_url if hasattr(w, "registrar_url") else None,
            "creation_date":    _str(w.creation_date),
            "expiration_date":  _str(w.expiration_date),
            "updated_date":     _str(w.updated_date),
            "name_servers":     list(w.name_servers) if w.name_servers else [],
            "dnssec":           w.dnssec if hasattr(w, "dnssec") else None,
            "status":           _str(w.status),
            "emails":           _str(w.emails),
        }
    except Exception as e:
        logger.error(f"WHOIS failed: {e}")
        return {}

# ─────────────────────── SUBDOMAIN SCANNER ───────────────────────
def scan_subdomain(sub, wildcard_ip=None):
    full = f"{sub}.{DOMAIN}"
    ip = resolve_ip(full)
    if not ip:
        return

    # Wildcard false-positive filter
    is_wildcard = (ip == wildcard_ip) if wildcard_ip else False

    # Parallel: geo, ports, TLS, HTTP
    with ThreadPoolExecutor(max_workers=4) as ex:
        fut_geo  = ex.submit(get_geo_ip, ip)
        fut_port = ex.submit(scan_ports, ip)
        fut_tls  = ex.submit(get_tls_info, full)
        fut_http = ex.submit(probe_http, full)
        fut_dns  = ex.submit(get_dns_records, full)

    geo   = fut_geo.result()
    ports = fut_port.result()
    tls   = fut_tls.result()
    http  = fut_http.result()
    dns_r = fut_dns.result()

    data = {
        "subdomain":    full,
        "ip":           ip,
        "reverse_dns":  reverse_dns(ip),
        "is_wildcard":  is_wildcard,
        "geo":          geo,
        "open_ports":   ports,
        "tls":          tls,
        "http":         http,
        "dns":          dns_r,
        "scan_time":    datetime.now().isoformat(),
    }

    with _lock:
        RESULTS["subdomains"].append(data)

    # Pretty terminal output
    wc_tag = Fore.YELLOW + " [WILDCARD?]" if is_wildcard else ""
    print(Fore.GREEN + f"\n[FOUND] {full} → {ip}{wc_tag}")
    if geo.get("country"):
        print(Fore.CYAN   + f"  ↳ Location : {geo['country']} / {geo.get('city','?')}")
        print(Fore.YELLOW + f"  ↳ Provider : {geo.get('org','unknown')}")
    if ports:
        print(Fore.MAGENTA+ f"  ↳ Ports    : {ports}")
    if tls.get("tls") and tls.get("cn"):
        print(Fore.BLUE   + f"  ↳ TLS CN   : {tls['cn']} (expires {tls.get('not_after','')})")
    if http.get("https_status") or http.get("http_status"):
        statuses = []
        if http.get("https_status"): statuses.append(f"HTTPS:{http['https_status']}")
        if http.get("http_status"):  statuses.append(f"HTTP:{http['http_status']}")
        print(Fore.WHITE  + f"  ↳ HTTP     : {' | '.join(statuses)}")
        if http.get("title"):
            print(Fore.WHITE + f"  ↳ Title    : {http['title']}")
        if http.get("waf_cdn"):
            print(Fore.RED + f"  ↳ WAF/CDN  : {', '.join(http['waf_cdn'])}")
        if http.get("technologies"):
            techs = ", ".join(f"{k}={v}" for k, v in http["technologies"].items())
            print(Fore.CYAN + f"  ↳ Tech     : {techs}")

# ─────────────────────── EXPORT ───────────────────────
def save_results():
    # ── JSON ──
    json_path = os.path.join(OUTPUT_DIR, "results.json")
    with open(json_path, "w") as f:
        json.dump(RESULTS, f, indent=4, default=str)
    print(Fore.GREEN + f"[+] JSON saved: {json_path}")

    # ── CSV ──
    csv_path = os.path.join(OUTPUT_DIR, "results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Subdomain", "IP", "Country", "City", "Provider",
            "Reverse DNS", "Open Ports", "HTTPS Status", "HTTP Status",
            "Page Title", "WAF/CDN", "TLS CN", "TLS Expiry",
            "Server", "X-Powered-By", "Is Wildcard"
        ])
        for r in RESULTS["subdomains"]:
            writer.writerow([
                r["subdomain"],
                r["ip"],
                r["geo"].get("country"),
                r["geo"].get("city"),
                r["geo"].get("org"),
                r["reverse_dns"],
                ", ".join(str(p) for p in r["open_ports"]),
                r["http"].get("https_status"),
                r["http"].get("http_status"),
                r["http"].get("title"),
                ", ".join(r["http"].get("waf_cdn", [])),
                r["tls"].get("cn"),
                r["tls"].get("not_after"),
                r["http"].get("server"),
                r["http"].get("x_powered_by"),
                r["is_wildcard"],
            ])
    print(Fore.GREEN + f"[+] CSV saved: {csv_path}")

    # ── HTML Report ──
    html_path = os.path.join(OUTPUT_DIR, "report.html")
    _write_html_report(html_path)
    print(Fore.GREEN + f"[+] HTML report: {html_path}")

def _write_html_report(path):
    rows = ""
    for r in sorted(RESULTS["subdomains"], key=lambda x: x["subdomain"]):
        ports = ", ".join(str(p) for p in r["open_ports"]) or "—"
        waf   = ", ".join(r["http"].get("waf_cdn", [])) or "—"
        rows += f"""
        <tr class="{'wildcard' if r['is_wildcard'] else ''}">
          <td>{r['subdomain']}</td>
          <td>{r['ip']}</td>
          <td>{r['geo'].get('country','?')} / {r['geo'].get('city','?')}</td>
          <td>{r['geo'].get('org','?')}</td>
          <td>{ports}</td>
          <td>{r['http'].get('https_status','') or ''} {r['http'].get('http_status','') or ''}</td>
          <td class="title-cell">{r['http'].get('title') or '—'}</td>
          <td class="waf">{waf}</td>
          <td>{r['tls'].get('cn') or '—'}</td>
          <td>{r['http'].get('server') or '—'}</td>
        </tr>"""

    di = RESULTS.get("domain_info", {})
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report – {DOMAIN}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --green: #3fb950;
    --blue: #58a6ff; --yellow: #d29922; --red: #f85149;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; padding: 2rem; }}
  h1 {{ color: var(--green); font-size: 1.6rem; margin-bottom: .4rem; }}
  .meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 2rem; }}
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; margin-bottom: 1.5rem; }}
  .section h2 {{ color: var(--blue); font-size: 1rem; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: .08em; }}
  .kv {{ display: grid; grid-template-columns: 180px 1fr; gap: .3rem .8rem; }}
  .kv span:nth-child(odd) {{ color: var(--muted); }}
  table {{ width: 100%; border-collapse: collapse; font-size: .78rem; }}
  th {{ background: #1c2128; color: var(--muted); text-align: left; padding: .5rem .7rem; border-bottom: 1px solid var(--border); white-space: nowrap; }}
  td {{ padding: .45rem .7rem; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover td {{ background: #1c2128; }}
  tr.wildcard td {{ color: var(--yellow); }}
  .waf {{ color: var(--red); font-weight: bold; }}
  .title-cell {{ max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .stat {{ display: inline-block; background: #1c2128; border: 1px solid var(--border); border-radius: 6px; padding: .4rem 1rem; margin-right: .6rem; }}
  .stat .num {{ font-size: 1.8rem; color: var(--green); }}
  .stat .label {{ color: var(--muted); font-size: .75rem; }}
</style>
</head>
<body>
<h1>⚡ Domain Recon Report</h1>
<div class="meta">Target: <b>{DOMAIN}</b> · Generated: {datetime.now():%Y-%m-%d %H:%M:%S}</div>

<div class="section">
  <h2>Summary</h2>
  <div style="margin-bottom:1rem">
    <div class="stat"><div class="num">{len(RESULTS['subdomains'])}</div><div class="label">Subdomains</div></div>
    <div class="stat"><div class="num">{sum(1 for r in RESULTS['subdomains'] if r['http'].get('https_status'))}</div><div class="label">HTTP Live</div></div>
    <div class="stat"><div class="num">{sum(1 for r in RESULTS['subdomains'] if r['tls'].get('tls'))}</div><div class="label">TLS Enabled</div></div>
    <div class="stat"><div class="num">{sum(1 for r in RESULTS['subdomains'] if r['http'].get('waf_cdn'))}</div><div class="label">WAF/CDN</div></div>
  </div>
</div>

<div class="section">
  <h2>Domain WHOIS</h2>
  <div class="kv">
    <span>Registrar</span><span>{di.get('registrar','—')}</span>
    <span>Created</span><span>{di.get('creation_date','—')}</span>
    <span>Expires</span><span>{di.get('expiration_date','—')}</span>
    <span>Name Servers</span><span>{', '.join(di.get('name_servers',[]))}</span>
    <span>DNSSEC</span><span>{di.get('dnssec','—')}</span>
  </div>
</div>

<div class="section">
  <h2>Discovered Subdomains ({len(RESULTS['subdomains'])})</h2>
  <table>
    <thead>
      <tr>
        <th>Subdomain</th><th>IP</th><th>Location</th><th>Provider / ASN</th>
        <th>Open Ports</th><th>HTTP Status</th><th>Page Title</th>
        <th>WAF / CDN</th><th>TLS CN</th><th>Server</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

# ─────────────────────── MAIN ───────────────────────
def main():
    global DOMAIN
    requests.packages.urllib3.disable_warnings()  # suppress SSL warnings

    if len(sys.argv) > 1:
        DOMAIN = sys.argv[1].strip()
    else:
        DOMAIN = input(Fore.BLUE + "Enter target domain (example.com): ").strip()

    RESULTS["meta"]["target"] = DOMAIN

    print(Fore.BLUE + Style.BRIGHT + "\n" + "═"*55)
    print(Fore.BLUE + Style.BRIGHT + "  ADVANCED DOMAIN RECON & NETWORK MAPPING TOOL")
    print(Fore.BLUE + Style.BRIGHT + "═"*55 + "\n")

    # 1. WHOIS
    print(Fore.MAGENTA + "[1/5] Collecting WHOIS / Domain Info...")
    RESULTS["domain_info"] = get_domain_info(DOMAIN)

    # 2. ROOT DNS
    print(Fore.MAGENTA + "[2/5] Fetching root DNS records...")
    RESULTS["dns_records"] = get_dns_records(DOMAIN)
    main_ip = resolve_ip(DOMAIN)
    if main_ip:
        print(Fore.CYAN + f"      Root IP: {main_ip}")

    # 3. WILDCARD DETECTION
    print(Fore.MAGENTA + "[3/5] Checking for wildcard DNS (false-positive guard)...")
    wildcard_ip = detect_wildcard(DOMAIN)

    # 4. LOAD WORDLIST
    if not os.path.exists(WORDLIST):
        print(Fore.RED + f"Wordlist not found: {WORDLIST}")
        print(Fore.YELLOW + "Falling back to a minimal built-in list.")
        subs = [
            "www","mail","ftp","smtp","pop","imap","vpn","remote","portal",
            "api","dev","staging","test","beta","admin","dashboard","login",
            "app","static","cdn","media","blog","shop","store","secure","help",
            "support","docs","wiki","forum","git","svn","jira","confluence",
            "jenkins","ci","build","monitor","status","ns1","ns2","mx","webmail"
        ]
    else:
        with open(WORDLIST, "r", errors="ignore") as f:
            subs = [line.strip() for line in f if line.strip()]

    print(Fore.MAGENTA + f"[4/5] Scanning {len(subs)} subdomains with {THREADS} threads...")

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(scan_subdomain, s, wildcard_ip): s for s in subs}
        done = 0
        for fut in as_completed(futures):
            done += 1
            if done % 100 == 0:
                print(Fore.BLUE + f"      Progress: {done}/{len(subs)} checked, "
                      f"{len(RESULTS['subdomains'])} found")
            try:
                fut.result()
            except Exception as e:
                logger.debug(f"Error scanning {futures[fut]}: {e}")

    # 5. SAVE
    print(Fore.MAGENTA + "\n[5/5] Saving results...")
    save_results()

    # SUMMARY
    total = len(RESULTS["subdomains"])
    live  = sum(1 for r in RESULTS["subdomains"] if r["http"].get("https_status") or r["http"].get("http_status"))
    tls_c = sum(1 for r in RESULTS["subdomains"] if r["tls"].get("tls"))
    waf_c = sum(1 for r in RESULTS["subdomains"] if r["http"].get("waf_cdn"))

    print(Fore.GREEN + Style.BRIGHT + "\n" + "═"*55)
    print(Fore.GREEN + Style.BRIGHT + "  SCAN COMPLETE")
    print(Fore.GREEN + f"  Subdomains found  : {total}")
    print(Fore.GREEN + f"  Live HTTP/S        : {live}")
    print(Fore.GREEN + f"  TLS-enabled        : {tls_c}")
    print(Fore.GREEN + f"  WAF/CDN protected  : {waf_c}")
    print(Fore.CYAN  + f"  Log                : {log_path}")
    print(Fore.BLUE  + Style.BRIGHT + "═"*55 + "\n")

if __name__ == "__main__":
    main()

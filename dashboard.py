import csv
import io
import ipaddress
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import dns.exception
import dns.resolver
import requests
import streamlit as st


# =========================================================
# APP CONFIG
# =========================================================

APP_NAME = "Domain Checker Pro"
TIMEOUT = 10
MAX_REDIRECTS = 8
MAX_BULK_DOMAINS = 25

# Session-based limits. These reduce accidental/spammy repeated scans.
# They are NOT a replacement for reverse-proxy/CDN rate limiting.
SINGLE_SCAN_LIMIT = 12
SINGLE_SCAN_WINDOW_SECONDS = 60
BULK_SCAN_LIMIT = 2
BULK_SCAN_WINDOW_SECONDS = 60

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151 Safari/537.36 DomainCheckerPro/5.0"
)

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

st.set_page_config(
    page_title=APP_NAME,
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)

for key, default in {
    "scan_history": [],
    "domain_report": None,
    "single_scan_times": [],
    "bulk_scan_times": [],
    "bulk_results": [],
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


# =========================================================
# PROFESSIONAL DARK UI
# =========================================================

st.markdown(
    """
<style>
:root {
    --bg: #080c12;
    --panel: #0d141d;
    --panel2: #101923;
    --border: #1f2b38;
    --border2: #2b3c4d;
    --text: #edf3f9;
    --muted: #8191a3;
    --accent: #2d83b5;
    --accent2: #4ba1cf;
    --ok: #4fc38a;
    --warn: #d8a64d;
    --bad: #df6c74;
}

html, body, [class*="css"] {
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

.stApp {
    color: var(--text);
    background:
        radial-gradient(circle at 15% 0%, rgba(45,131,181,.12), transparent 28%),
        radial-gradient(circle at 85% 8%, rgba(28,76,110,.08), transparent 24%),
        var(--bg);
}

.block-container {
    max-width: 1500px;
    padding-top: 1.5rem;
    padding-bottom: 4rem;
}

header[data-testid="stHeader"] { background: transparent; }

.dc-hero {
    background: linear-gradient(135deg, rgba(18,29,41,.98), rgba(10,16,24,.98));
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 28px 30px;
    margin-bottom: 22px;
    box-shadow: 0 14px 34px rgba(0,0,0,.22);
}

.dc-eyebrow {
    color: #718599;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1.6px;
    text-transform: uppercase;
    margin-bottom: 7px;
}

.dc-title {
    color: #f5f8fb;
    font-size: 36px;
    line-height: 1.15;
    font-weight: 720;
    letter-spacing: -1px;
}

.dc-subtitle {
    color: #8fa0b1;
    font-size: 14px;
    margin-top: 9px;
}

.stTextInput label,
.stTextArea label {
    color: #a9b6c4 !important;
    font-weight: 600 !important;
    font-size: 13px !important;
}

.stTextInput input,
.stTextArea textarea {
    background: #0c131c !important;
    color: #e7eef6 !important;
    border: 1px solid var(--border2) !important;
    border-radius: 9px !important;
    font-family: "Cascadia Code", Consolas, monospace !important;
}

.stButton button,
.stDownloadButton button {
    background: #176f9f !important;
    color: #fff !important;
    border: 1px solid #2183b6 !important;
    border-radius: 8px !important;
    min-height: 41px !important;
    padding: 8px 18px !important;
    font-weight: 650 !important;
    box-shadow: none !important;
}

.stButton button:hover,
.stDownloadButton button:hover {
    background: #1c7eaf !important;
    border-color: #3293c3 !important;
}

.dc-card {
    background: linear-gradient(180deg, #0e1620, #0c131b);
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 17px 18px;
    min-height: 105px;
    box-shadow: 0 6px 18px rgba(0,0,0,.13);
}

.dc-card-label {
    color: #6f8195;
    font-size: 10px;
    font-weight: 750;
    letter-spacing: 1.1px;
    text-transform: uppercase;
    margin-bottom: 9px;
}

.dc-card-value {
    color: #eef4fa;
    font-size: 20px;
    font-weight: 680;
    word-break: break-word;
}

.dc-card-sub {
    color: #6e8093;
    font-size: 11px;
    margin-top: 5px;
}

.dc-score {
    font-size: 32px;
    font-weight: 800;
    letter-spacing: -1px;
}

.ok { color: var(--ok); }
.warn { color: var(--warn); }
.bad { color: var(--bad); }
.neutral { color: #dce5ee; }

.issue-high {
    border-left: 3px solid var(--bad);
    padding-left: 12px;
    margin-bottom: 12px;
}

.issue-medium {
    border-left: 3px solid var(--warn);
    padding-left: 12px;
    margin-bottom: 12px;
}

.issue-low {
    border-left: 3px solid #5a91b3;
    padding-left: 12px;
    margin-bottom: 12px;
}

.issue-title {
    color: #e7edf5;
    font-weight: 650;
}

.issue-desc {
    color: #8fa0b1;
    font-size: 13px;
    margin-top: 3px;
}

code, pre {
    font-family: "Cascadia Code", Consolas, monospace !important;
}

div[data-testid="stCodeBlock"] {
    border: 1px solid #1e2a36;
    border-radius: 9px;
}

button[data-baseweb="tab"] {
    color: #8394a6 !important;
    font-weight: 650 !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #dceaf4 !important;
}

[data-testid="stDataFrame"] {
    border: 1px solid var(--border);
    border-radius: 9px;
    overflow: hidden;
}

#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
</style>
""",
    unsafe_allow_html=True,
)


# =========================================================
# GENERAL HELPERS
# =========================================================

def esc(value):
    import html
    return html.escape(str(value))


def fmt(value, fallback="-"):
    if value is None or value == "":
        return fallback
    return value


def status_class(ok=None, warning=False):
    if warning:
        return "warn"
    if ok is True:
        return "ok"
    if ok is False:
        return "bad"
    return "neutral"


def card(label, value, css_class="neutral", sub=None, score=False):
    sub_html = f'<div class="dc-card-sub">{esc(sub)}</div>' if sub else ""
    extra = " dc-score" if score else ""
    return f"""
    <div class="dc-card">
        <div class="dc-card-label">{esc(label)}</div>
        <div class="dc-card-value {css_class}{extra}">{esc(value)}</div>
        {sub_html}
    </div>
    """


def parse_iso_date(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


# =========================================================
# RATE LIMITING (SESSION-BASED)
# =========================================================

def check_rate_limit(key, limit, window_seconds):
    now = time.time()
    timestamps = [
        ts for ts in st.session_state.get(key, [])
        if now - ts < window_seconds
    ]

    if len(timestamps) >= limit:
        wait_seconds = max(1, int(window_seconds - (now - timestamps[0])))
        return False, wait_seconds

    timestamps.append(now)
    st.session_state[key] = timestamps
    return True, 0


# =========================================================
# SSRF / TARGET SAFETY
# =========================================================

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
}

BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home",
    ".lan",
)


def normalize_domain(value: str) -> str:
    value = (value or "").strip()

    if not value:
        raise ValueError("Domain belum diisi.")

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.username or parsed.password:
        raise ValueError("Username/password di URL tidak diizinkan.")

    if parsed.port not in (None, 80, 443):
        raise ValueError("Port custom tidak diizinkan. Hanya HTTP/HTTPS standar.")

    host = parsed.hostname or ""

    if not host:
        raise ValueError("Format domain tidak valid.")

    host = host.rstrip(".").lower()

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass

    return host


def ip_is_public(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text)
        return ip.is_global
    except ValueError:
        return False


def resolve_host_ips(host: str):
    ips = set()

    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM,
        ):
            if family == socket.AF_INET:
                ips.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ips.add(sockaddr[0])
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolve gagal: {exc}")

    return sorted(ips)


def validate_public_target(host: str):
    host_lower = host.lower().rstrip(".")

    if host_lower in BLOCKED_HOSTS:
        raise ValueError("Target lokal/internal tidak diizinkan.")

    if any(host_lower.endswith(suffix) for suffix in BLOCKED_SUFFIXES):
        raise ValueError("Hostname lokal/internal tidak diizinkan.")

    # Direct IP input
    try:
        ip = ipaddress.ip_address(host_lower)
        if not ip.is_global:
            raise ValueError("IP private, loopback, link-local, reserved, atau non-public tidak diizinkan.")
        return [str(ip)]
    except ValueError as exc:
        # If host looks like an IP but is blocked, preserve the explicit block error.
        if any(ch.isdigit() for ch in host_lower) and re.fullmatch(r"[0-9a-fA-F:.]+", host_lower):
            try:
                ipaddress.ip_address(host_lower)
            except ValueError:
                pass
            else:
                raise exc

    ips = resolve_host_ips(host_lower)

    if not ips:
        raise ValueError("Domain tidak resolve ke IP.")

    blocked = [ip for ip in ips if not ip_is_public(ip)]

    if blocked:
        raise ValueError(
            "Target ditolak karena resolve ke IP non-public/internal: "
            + ", ".join(blocked)
        )

    return ips


def validate_url_target(url: str):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Hanya URL HTTP/HTTPS yang diizinkan.")

    if parsed.username or parsed.password:
        raise ValueError("Credential pada URL tidak diizinkan.")

    if parsed.port not in (None, 80, 443):
        raise ValueError("Redirect ke port non-standar ditolak.")

    host = parsed.hostname
    if not host:
        raise ValueError("Redirect URL tidak memiliki hostname valid.")

    validate_public_target(host)
    return True


# =========================================================
# SAFE HTTP WITH VALIDATED REDIRECTS
# =========================================================

def safe_http_get(url: str, max_redirects=MAX_REDIRECTS):
    current_url = url
    history = []

    for _ in range(max_redirects + 1):
        validate_url_target(current_url)

        response = session.get(
            current_url,
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")

            history.append({
                "status": response.status_code,
                "url": current_url,
                "location": location,
            })

            if not location:
                return response, history, current_url

            next_url = urljoin(current_url, location)
            validate_url_target(next_url)
            current_url = next_url
            continue

        history.append({
            "status": response.status_code,
            "url": current_url,
            "location": None,
        })

        return response, history, current_url

    raise requests.TooManyRedirects(
        f"Redirect lebih dari {max_redirects} hop."
    )


# =========================================================
# HTML / SEO PARSER
# =========================================================

class SEOParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title_parts = []
        self.meta_description = None
        self.meta_robots = None
        self.canonical = None
        self.lang = None
        self.h1_count = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs_dict = {str(k).lower(): v for k, v in attrs if k}

        if tag == "html":
            self.lang = attrs_dict.get("lang")
        elif tag == "title":
            self.in_title = True
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "meta":
            name = (attrs_dict.get("name") or "").lower()
            content = attrs_dict.get("content")
            if name == "description" and content:
                self.meta_description = content.strip()
            if name == "robots" and content:
                self.meta_robots = content.strip()
        elif tag == "link":
            rel = attrs_dict.get("rel") or ""
            href = attrs_dict.get("href")
            rel_values = rel.lower().split() if isinstance(rel, str) else [str(x).lower() for x in rel]
            if "canonical" in rel_values and href:
                self.canonical = href.strip()

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)

    def result(self):
        title = re.sub(r"\s+", " ", " ".join(self.title_parts)).strip()
        desc = re.sub(r"\s+", " ", self.meta_description).strip() if self.meta_description else None

        return {
            "title": title or None,
            "title_length": len(title) if title else 0,
            "meta_description": desc,
            "meta_description_length": len(desc) if desc else 0,
            "canonical": self.canonical,
            "meta_robots": self.meta_robots,
            "html_lang": self.lang,
            "h1_count": self.h1_count,
        }


# =========================================================
# DNS
# =========================================================

def safe_dns_resolve(domain: str, record_type: str):
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=TIMEOUT)
        values = []

        for answer in answers:
            if record_type == "MX":
                values.append({
                    "priority": int(answer.preference),
                    "host": str(answer.exchange).rstrip("."),
                })
            elif record_type == "SOA":
                values.append({
                    "mname": str(answer.mname).rstrip("."),
                    "rname": str(answer.rname).rstrip("."),
                    "serial": int(answer.serial),
                    "refresh": int(answer.refresh),
                    "retry": int(answer.retry),
                    "expire": int(answer.expire),
                    "minimum": int(answer.minimum),
                })
            else:
                values.append(str(answer).strip('"').rstrip("."))

        return values

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        return [{"error": str(exc)}]
    except Exception as exc:
        return [{"error": str(exc)}]


def check_dns(domain: str):
    validate_public_target(domain)

    types = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "CAA", "SOA", "DS"]
    data = {rtype: safe_dns_resolve(domain, rtype) for rtype in types}

    ds = data.get("DS", [])
    data["dnssec_detected"] = bool(
        ds and not (isinstance(ds[0], dict) and "error" in ds[0])
    )

    return data


def extract_txt_strings(txt_records):
    return [item for item in (txt_records or []) if isinstance(item, str)]


def check_email_security(domain: str, dns_data):
    txt = extract_txt_strings(dns_data.get("TXT", []))
    spf = [x for x in txt if x.lower().startswith("v=spf1")]

    dmarc_records = safe_dns_resolve(f"_dmarc.{domain}", "TXT")
    dmarc_txt = [
        x for x in dmarc_records
        if isinstance(x, str) and x.lower().startswith("v=dmarc1")
    ]

    mx = dns_data.get("MX", [])

    return {
        "spf_present": bool(spf),
        "spf_records": spf,
        "dmarc_present": bool(dmarc_txt),
        "dmarc_records": dmarc_txt,
        "mx_present": bool(mx),
        "mx_records": mx,
        "dkim_note": "DKIM membutuhkan selector; tidak bisa dipastikan hanya dari nama domain.",
    }


# =========================================================
# HTTP / HTTPS
# =========================================================

def check_http(url: str):
    result = {
        "requested_url": url,
        "status_code": None,
        "final_url": None,
        "response_time_ms": None,
        "redirect_chain": [],
        "server": None,
        "content_type": None,
        "response_bytes": None,
        "headers": {},
        "seo": {},
        "error": None,
    }

    try:
        start = time.perf_counter()
        response, history, final_url = safe_http_get(url)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

        result["status_code"] = response.status_code
        result["final_url"] = final_url
        result["response_time_ms"] = elapsed_ms
        result["redirect_chain"] = history
        result["server"] = response.headers.get("Server")
        result["content_type"] = response.headers.get("Content-Type")
        result["response_bytes"] = len(response.content)
        result["headers"] = dict(response.headers)

        content_type = (response.headers.get("Content-Type") or "").lower()

        if "text/html" in content_type:
            parser = SEOParser()
            try:
                parser.feed(response.text[:2_000_000])
                result["seo"] = parser.result()
            except Exception:
                result["seo"] = {}

    except ValueError as exc:
        result["error"] = f"Blocked target: {exc}"
    except requests.exceptions.SSLError as exc:
        result["error"] = f"SSL error: {exc}"
    except requests.exceptions.ConnectTimeout:
        result["error"] = "Connection timeout."
    except requests.exceptions.ReadTimeout:
        result["error"] = "Read timeout."
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"Connection error: {exc}"
    except requests.RequestException as exc:
        result["error"] = str(exc)

    return result


def check_resource(url: str):
    result = {
        "url": url,
        "status": None,
        "final_url": None,
        "content_type": None,
        "error": None,
    }

    try:
        response, _, final_url = safe_http_get(url)
        result["status"] = response.status_code
        result["final_url"] = final_url
        result["content_type"] = response.headers.get("Content-Type")
    except Exception as exc:
        result["error"] = str(exc)

    return result


# =========================================================
# SSL / TLS
# =========================================================

def check_ssl(domain: str):
    result = {
        "valid": False,
        "tls_version": None,
        "cipher": None,
        "subject": {},
        "issuer": {},
        "serial_number": None,
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "san": [],
        "error": None,
    }

    try:
        validate_public_target(domain)
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["valid"] = True
                result["tls_version"] = ssock.version()

                cipher = ssock.cipher()
                if cipher:
                    result["cipher"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                    }

                result["subject"] = dict(x[0] for x in cert.get("subject", []))
                result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                result["serial_number"] = cert.get("serialNumber")

                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")

                if not_before:
                    result["valid_from"] = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(not_before),
                        tz=timezone.utc,
                    ).isoformat()

                if not_after:
                    expiry = datetime.fromtimestamp(
                        ssl.cert_time_to_seconds(not_after),
                        tz=timezone.utc,
                    )
                    result["valid_until"] = expiry.isoformat()
                    result["days_remaining"] = (expiry - datetime.now(timezone.utc)).days

                result["san"] = [
                    value
                    for key, value in cert.get("subjectAltName", [])
                    if key == "DNS"
                ]

    except Exception as exc:
        result["error"] = str(exc)

    return result


# =========================================================
# RDAP
# =========================================================

def get_vcard_value(vcard_array, key):
    try:
        for item in vcard_array[1]:
            if item[0] == key:
                return item[3]
    except Exception:
        pass
    return None


def check_rdap(domain: str):
    result = {
        "registrar": None,
        "created": None,
        "updated": None,
        "expires": None,
        "statuses": [],
        "nameservers": [],
        "handle": None,
        "domain_age_days": None,
        "days_to_expiry": None,
        "error": None,
    }

    try:
        # Fixed external RDAP endpoint, not user-controlled.
        response = session.get(
            f"https://rdap.org/domain/{domain}",
            timeout=TIMEOUT,
            allow_redirects=True,
        )

        if response.status_code != 200:
            result["error"] = f"RDAP HTTP {response.status_code}"
            return result

        data = response.json()
        result["handle"] = data.get("handle")
        result["statuses"] = data.get("status", [])

        for ns in data.get("nameservers", []):
            name = ns.get("ldhName") or ns.get("unicodeName")
            if name:
                result["nameservers"].append(name.lower())

        for event in data.get("events", []):
            action = event.get("eventAction")
            date = event.get("eventDate")

            if action == "registration":
                result["created"] = date
            elif action == "expiration":
                result["expires"] = date
            elif action in ("last changed", "last update of RDAP database"):
                if not result["updated"]:
                    result["updated"] = date

        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                result["registrar"] = get_vcard_value(entity.get("vcardArray"), "fn")
                if not result["registrar"]:
                    result["registrar"] = entity.get("handle")
                break

        created_dt = parse_iso_date(result["created"])
        expires_dt = parse_iso_date(result["expires"])
        now = datetime.now(timezone.utc)

        if created_dt:
            result["domain_age_days"] = (now - created_dt).days
        if expires_dt:
            result["days_to_expiry"] = (expires_dt - now).days

    except Exception as exc:
        result["error"] = str(exc)

    return result


# =========================================================
# SECURITY / INFRASTRUCTURE
# =========================================================

def security_headers(headers):
    wanted = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "X-Frame-Options",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy",
    }

    lower = {k.lower(): v for k, v in headers.items()}
    result = {}

    for header, label in wanted.items():
        value = lower.get(header.lower())
        result[label] = {
            "present": value is not None,
            "value": value,
        }

    return result


def detect_cloudflare(dns_data, https_data):
    reasons = []
    ns_values = dns_data.get("NS", [])

    if any("cloudflare.com" in str(ns).lower() for ns in ns_values):
        reasons.append("Cloudflare nameserver")

    headers = https_data.get("headers", {})
    lower = {k.lower(): str(v).lower() for k, v in headers.items()}

    if "cf-ray" in lower:
        reasons.append("CF-RAY response header")

    if "cloudflare" in lower.get("server", ""):
        reasons.append("Cloudflare Server header")

    return {"detected": bool(reasons), "reasons": reasons}


# =========================================================
# HEALTH SCORE
# =========================================================

def build_health(report):
    score = 100
    issues = []

    dns_data = report["dns"]
    http_data = report["http"]
    https_data = report["https"]
    ssl_data = report["ssl"]
    seo = https_data.get("seo", {})
    sec = report["security_headers"]
    email_sec = report["email_security"]
    robots = report["robots_txt"]
    sitemap = report["sitemap_xml"]
    rdap = report["rdap"]

    dns_ok = bool(dns_data.get("A") or dns_data.get("AAAA"))
    if not dns_ok:
        score -= 25
        issues.append({
            "severity": "HIGH",
            "title": "DNS resolution bermasalah",
            "description": "A/AAAA record tidak berhasil ditemukan.",
        })

    https_code = https_data.get("status_code")
    if https_code is None:
        score -= 20
        issues.append({
            "severity": "HIGH",
            "title": "HTTPS tidak dapat diakses",
            "description": https_data.get("error") or "Tidak ada response HTTPS.",
        })
    elif https_code >= 500:
        score -= 15
        issues.append({
            "severity": "HIGH",
            "title": f"Server mengembalikan HTTP {https_code}",
            "description": "Periksa aplikasi, origin, resource server, dan log error.",
        })
    elif https_code >= 400:
        score -= 10
        issues.append({
            "severity": "MEDIUM",
            "title": f"HTTPS mengembalikan HTTP {https_code}",
            "description": "Target dapat dijangkau tetapi response bukan status sukses.",
        })

    if not ssl_data.get("valid"):
        score -= 20
        issues.append({
            "severity": "HIGH",
            "title": "Sertifikat SSL/TLS tidak valid",
            "description": ssl_data.get("error") or "Validasi sertifikat gagal.",
        })
    else:
        days = ssl_data.get("days_remaining")
        if days is not None and days < 30:
            score -= 8
            issues.append({
                "severity": "MEDIUM",
                "title": f"SSL akan berakhir dalam {days} hari",
                "description": "Jadwalkan renewal sebelum sertifikat berakhir.",
            })

    response_ms = https_data.get("response_time_ms")
    if response_ms is not None:
        if response_ms > 3000:
            score -= 8
            issues.append({
                "severity": "MEDIUM",
                "title": "Response time sangat lambat",
                "description": f"HTTPS response sekitar {response_ms} ms.",
            })
        elif response_ms > 1200:
            score -= 4
            issues.append({
                "severity": "LOW",
                "title": "Response time cukup lambat",
                "description": f"HTTPS response sekitar {response_ms} ms.",
            })

    if http_data.get("status_code") is not None:
        if not (http_data.get("final_url") or "").lower().startswith("https://"):
            score -= 6
            issues.append({
                "severity": "MEDIUM",
                "title": "HTTP tidak diarahkan ke HTTPS",
                "description": "Konfigurasikan redirect HTTP → HTTPS.",
            })

    if not seo.get("title"):
        score -= 4
        issues.append({
            "severity": "LOW",
            "title": "Title tag tidak ditemukan",
            "description": "Tambahkan title yang relevan.",
        })

    if not seo.get("meta_description"):
        score -= 3
        issues.append({
            "severity": "LOW",
            "title": "Meta description tidak ditemukan",
            "description": "Tambahkan meta description.",
        })

    if "noindex" in (seo.get("meta_robots") or "").lower():
        score -= 10
        issues.append({
            "severity": "MEDIUM",
            "title": "Meta robots mengandung noindex",
            "description": "Homepage meminta mesin pencari untuk tidak mengindeks halaman.",
        })

    if robots.get("status") != 200:
        score -= 2
        issues.append({
            "severity": "LOW",
            "title": "robots.txt tidak berstatus 200",
            "description": "Periksa robots.txt bila dibutuhkan.",
        })

    if sitemap.get("status") != 200:
        score -= 2
        issues.append({
            "severity": "LOW",
            "title": "sitemap.xml tidak berstatus 200",
            "description": "Periksa sitemap bila dibutuhkan.",
        })

    missing_security = [name for name, data in sec.items() if not data["present"]]
    if missing_security:
        score -= min(12, len(missing_security) * 2)
        issues.append({
            "severity": "MEDIUM" if len(missing_security) >= 3 else "LOW",
            "title": "Security header tidak lengkap",
            "description": "Tidak terdeteksi: " + ", ".join(missing_security),
        })

    if email_sec["mx_present"]:
        if not email_sec["spf_present"]:
            score -= 3
        if not email_sec["dmarc_present"]:
            score -= 3

    days_to_expiry = rdap.get("days_to_expiry")
    if days_to_expiry is not None and days_to_expiry < 30:
        score -= 5
        issues.append({
            "severity": "MEDIUM",
            "title": f"Domain akan berakhir dalam {days_to_expiry} hari",
            "description": "Pastikan renewal dilakukan sebelum expiry.",
        })

    score = max(0, min(100, score))

    grade = (
        "Excellent" if score >= 90
        else "Healthy" if score >= 75
        else "Warning" if score >= 55
        else "Critical"
    )

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    issues.sort(key=lambda x: order.get(x["severity"], 99))

    return {"score": score, "grade": grade, "issues": issues}


# =========================================================
# FULL SCAN
# =========================================================

def run_scan(domain: str):
    validate_public_target(domain)

    report = {
        "domain": domain,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    with st.status("Menjalankan domain analysis...", expanded=True) as status:
        status.write("Validating public target...")
        validate_public_target(domain)

        status.write("Resolving DNS records...")
        report["dns"] = check_dns(domain)

        status.write("Checking SPF / DMARC / MX...")
        report["email_security"] = check_email_security(domain, report["dns"])

        status.write("Checking HTTP and HTTPS endpoints...")
        report["http"] = check_http(f"http://{domain}")
        report["https"] = check_http(f"https://{domain}")

        status.write("Inspecting SSL/TLS certificate...")
        report["ssl"] = check_ssl(domain)

        status.write("Retrieving RDAP registration data...")
        report["rdap"] = check_rdap(domain)

        status.write("Checking robots.txt and sitemap.xml...")
        report["robots_txt"] = check_resource(f"https://{domain}/robots.txt")
        report["sitemap_xml"] = check_resource(f"https://{domain}/sitemap.xml")

        status.write("Checking WWW / non-WWW behavior...")
        www_domain = domain if domain.startswith("www.") else f"www.{domain}"
        root_domain = domain[4:] if domain.startswith("www.") else domain

        # Only scan WWW variant if it resolves to public IP.
        try:
            validate_public_target(www_domain)
            www_result = check_http(f"https://{www_domain}")
        except Exception as exc:
            www_result = {"status_code": None, "final_url": None, "error": str(exc)}

        try:
            validate_public_target(root_domain)
            root_result = check_http(f"https://{root_domain}")
        except Exception as exc:
            root_result = {"status_code": None, "final_url": None, "error": str(exc)}

        report["www_check"] = {
            "www": www_result,
            "root": root_result,
        }

        status.write("Evaluating security headers...")
        report["security_headers"] = security_headers(report["https"].get("headers", {}))
        report["cloudflare"] = detect_cloudflare(report["dns"], report["https"])

        status.write("Calculating health score...")
        report["health"] = build_health(report)

        status.update(label="Analysis complete", state="complete", expanded=False)

    return report


# =========================================================
# UI RENDERERS
# =========================================================

def render_overview(report):
    health = report["health"]
    dns_data = report["dns"]
    https = report["https"]
    ssl_data = report["ssl"]
    cloudflare = report["cloudflare"]

    dns_ok = bool(dns_data.get("A") or dns_data.get("AAAA"))
    https_code = https.get("status_code")
    https_ok = https_code is not None and 200 <= https_code < 400
    ssl_ok = ssl_data.get("valid", False)
    response_ms = https.get("response_time_ms")

    score_class = "ok" if health["score"] >= 75 else "warn" if health["score"] >= 55 else "bad"

    cols = st.columns(6)

    with cols[0]:
        st.markdown(card("Health Score", f'{health["score"]}/100', score_class, health["grade"], score=True), unsafe_allow_html=True)

    with cols[1]:
        st.markdown(card("DNS", "Healthy" if dns_ok else "Problem", status_class(dns_ok), "A / AAAA resolution"), unsafe_allow_html=True)

    with cols[2]:
        st.markdown(card("HTTPS", str(https_code) if https_code is not None else "Error", status_class(https_ok), "Primary response"), unsafe_allow_html=True)

    with cols[3]:
        st.markdown(card("TLS", "Valid" if ssl_ok else "Invalid", status_class(ssl_ok), fmt(ssl_data.get("tls_version"))), unsafe_allow_html=True)

    with cols[4]:
        speed_class = "neutral"
        if response_ms is not None:
            speed_class = "ok" if response_ms < 800 else "warn" if response_ms < 2500 else "bad"
        st.markdown(card("Response Time", f"{response_ms} ms" if response_ms is not None else "-", speed_class, "HTTPS latency"), unsafe_allow_html=True)

    with cols[5]:
        st.markdown(card("Infrastructure", "Cloudflare" if cloudflare["detected"] else "Other", "neutral", "CDN / edge detection"), unsafe_allow_html=True)

    st.subheader("Detected Issues")

    if not health["issues"]:
        st.success("Tidak ada issue penting yang terdeteksi.")
    else:
        for issue in health["issues"][:10]:
            css = {
                "HIGH": "issue-high",
                "MEDIUM": "issue-medium",
                "LOW": "issue-low",
            }.get(issue["severity"], "issue-low")

            st.markdown(
                f"""
                <div class="{css}">
                    <div class="issue-title">{esc(issue["severity"])} · {esc(issue["title"])}</div>
                    <div class="issue-desc">{esc(issue["description"])}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_dns(report):
    dns_data = report["dns"]

    for rtype in ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "CAA", "SOA", "DS"]:
        with st.expander(rtype, expanded=rtype in ("A", "NS", "MX")):
            values = dns_data.get(rtype, [])
            if values:
                st.code(json.dumps(values, indent=2, ensure_ascii=False), language="json")
            else:
                st.caption("No record returned.")

    st.write("**DNSSEC DS record detected:**", "Yes" if dns_data.get("dnssec_detected") else "No")


def render_email_security(report):
    data = report["email_security"]
    cols = st.columns(3)

    with cols[0]:
        st.markdown(card("MX", "Present" if data["mx_present"] else "Missing", status_class(data["mx_present"]), "Mail exchanger"), unsafe_allow_html=True)

    with cols[1]:
        st.markdown(card("SPF", "Present" if data["spf_present"] else "Missing", status_class(data["spf_present"]), "TXT policy"), unsafe_allow_html=True)

    with cols[2]:
        st.markdown(card("DMARC", "Present" if data["dmarc_present"] else "Missing", status_class(data["dmarc_present"]), "_dmarc TXT"), unsafe_allow_html=True)

    st.subheader("MX Records")
    st.code(json.dumps(data["mx_records"], indent=2, ensure_ascii=False), language="json")
    st.subheader("SPF")
    st.code(json.dumps(data["spf_records"], indent=2, ensure_ascii=False), language="json")
    st.subheader("DMARC")
    st.code(json.dumps(data["dmarc_records"], indent=2, ensure_ascii=False), language="json")
    st.info(data["dkim_note"])


def render_http(report):
    http_data = report["http"]
    https_data = report["https"]
    www_data = report["www_check"]

    c1, c2 = st.columns(2)

    for col, label, data in [(c1, "HTTP", http_data), (c2, "HTTPS", https_data)]:
        with col:
            st.subheader(label)
            st.write("**Status:**", fmt(data.get("status_code")))
            st.write("**Final URL:**", fmt(data.get("final_url")))
            st.write("**Response time:**", f'{data.get("response_time_ms")} ms' if data.get("response_time_ms") is not None else "-")
            st.write("**Server:**", fmt(data.get("server")))
            st.write("**Content-Type:**", fmt(data.get("content_type")))
            st.write("**Response size:**", f'{data.get("response_bytes")} bytes' if data.get("response_bytes") is not None else "-")
            if data.get("error"):
                st.error(data["error"])

    st.subheader("Redirect Chain")

    for label, data in [("HTTP", http_data), ("HTTPS", https_data)]:
        with st.expander(f"{label} redirects", expanded=True):
            chain = data.get("redirect_chain", [])
            if not chain:
                st.caption("No redirect chain available.")
            for hop in chain:
                st.code(f'{hop["status"]}  {hop["url"]}', language="text")

    st.subheader("WWW vs Non-WWW")
    for label, data in [("WWW", www_data["www"]), ("NON-WWW", www_data["root"])]:
        st.write(
            f"**{label}:**",
            f'{data.get("status_code")} → {data.get("final_url")}'
            if data.get("status_code") is not None
            else fmt(data.get("error")),
        )


def render_ssl(report):
    data = report["ssl"]

    if data.get("valid"):
        st.success("TLS certificate validation succeeded.")
    else:
        st.error("TLS certificate validation failed.")

    c1, c2 = st.columns(2)

    with c1:
        st.write("**TLS version:**", fmt(data.get("tls_version")))
        st.write("**Valid from:**", fmt(data.get("valid_from")))
        st.write("**Valid until:**", fmt(data.get("valid_until")))
        st.write("**Days remaining:**", fmt(data.get("days_remaining")))
        st.write("**Serial number:**", fmt(data.get("serial_number")))
        if data.get("error"):
            st.error(data["error"])

    with c2:
        st.write("**Cipher:**")
        st.code(json.dumps(data.get("cipher"), indent=2, ensure_ascii=False), language="json")
        st.write("**Issuer:**")
        st.code(json.dumps(data.get("issuer", {}), indent=2, ensure_ascii=False), language="json")

    st.write("**Subject:**")
    st.code(json.dumps(data.get("subject", {}), indent=2, ensure_ascii=False), language="json")
    st.write("**Subject Alternative Names:**")
    st.code(json.dumps(data.get("san", []), indent=2, ensure_ascii=False), language="json")


def render_rdap(report):
    data = report["rdap"]

    if data.get("error"):
        st.warning(f'RDAP: {data["error"]}')

    c1, c2 = st.columns(2)

    with c1:
        st.write("**Registrar:**", fmt(data.get("registrar")))
        st.write("**Created:**", fmt(data.get("created")))
        st.write("**Updated:**", fmt(data.get("updated")))
        st.write("**Expires:**", fmt(data.get("expires")))
        st.write("**Domain age:**", f'{data.get("domain_age_days")} days' if data.get("domain_age_days") is not None else "-")
        st.write("**Days to expiry:**", fmt(data.get("days_to_expiry")))

    with c2:
        st.write("**RDAP Handle:**", fmt(data.get("handle")))
        st.write("**Domain Status:**")
        st.code(json.dumps(data.get("statuses", []), indent=2), language="json")
        st.write("**RDAP Nameservers:**")
        st.code(json.dumps(data.get("nameservers", []), indent=2), language="json")


def render_seo(report):
    seo = report["https"].get("seo", {})

    if not seo:
        st.warning("HTML SEO data tidak berhasil diekstrak.")
        return

    c1, c2 = st.columns(2)

    with c1:
        st.write("**Title:**", fmt(seo.get("title")))
        st.write("**Title length:**", seo.get("title_length", 0))
        st.write("**Meta description:**", fmt(seo.get("meta_description")))
        st.write("**Description length:**", seo.get("meta_description_length", 0))

    with c2:
        st.write("**Canonical:**", fmt(seo.get("canonical")))
        st.write("**Meta robots:**", fmt(seo.get("meta_robots")))
        st.write("**HTML language:**", fmt(seo.get("html_lang")))
        st.write("**H1 count:**", seo.get("h1_count", 0))

    st.divider()

    for label, data in [("robots.txt", report["robots_txt"]), ("sitemap.xml", report["sitemap_xml"])]:
        st.subheader(label)
        st.write("**Status:**", fmt(data.get("status")))
        st.write("**Final URL:**", fmt(data.get("final_url")))
        if data.get("error"):
            st.error(data["error"])


def render_security(report):
    for name, data in report["security_headers"].items():
        c1, c2 = st.columns([0.28, 0.72])

        with c1:
            if data["present"]:
                st.success(f"{name}: Present")
            else:
                st.warning(f"{name}: Missing")

        with c2:
            st.code(fmt(data.get("value")), language="text")

    with st.expander("All HTTPS response headers"):
        st.code(
            json.dumps(report["https"].get("headers", {}), indent=2, ensure_ascii=False),
            language="json",
        )


def render_recommendations(report):
    issues = report["health"]["issues"]

    if not issues:
        st.success("Tidak ada rekomendasi prioritas.")
        return

    for issue in issues:
        if issue["severity"] == "HIGH":
            st.error(f'**HIGH — {issue["title"]}**\n\n{issue["description"]}')
        elif issue["severity"] == "MEDIUM":
            st.warning(f'**MEDIUM — {issue["title"]}**\n\n{issue["description"]}')
        else:
            st.info(f'**LOW — {issue["title"]}**\n\n{issue["description"]}')


def add_history(report):
    item = {
        "checked_at": report["checked_at"],
        "domain": report["domain"],
        "score": report["health"]["score"],
        "grade": report["health"]["grade"],
        "https_status": report["https"].get("status_code"),
        "ssl_valid": report["ssl"].get("valid"),
        "response_time_ms": report["https"].get("response_time_ms"),
    }

    history = st.session_state["scan_history"]
    history.insert(0, item)
    st.session_state["scan_history"] = history[:100]


# =========================================================
# BULK SCAN
# =========================================================

def bulk_light_scan(raw_domain: str):
    try:
        domain = normalize_domain(raw_domain)
        validate_public_target(domain)
    except Exception as exc:
        return {
            "domain": raw_domain,
            "status": "BLOCKED / INVALID",
            "https": None,
            "ip": None,
            "response_ms": None,
            "ssl": None,
            "ssl_days": None,
            "final_url": None,
            "error": str(exc),
        }

    dns_a = safe_dns_resolve(domain, "A")
    ip = dns_a[0] if dns_a and isinstance(dns_a[0], str) else None

    https = check_http(f"https://{domain}")
    ssl_data = check_ssl(domain)

    code = https.get("status_code")
    if code is None:
        status = "OFFLINE / ERROR"
    elif 200 <= code < 400:
        status = "ONLINE"
    else:
        status = f"HTTP {code}"

    return {
        "domain": domain,
        "status": status,
        "https": code,
        "ip": ip,
        "response_ms": https.get("response_time_ms"),
        "ssl": "VALID" if ssl_data.get("valid") else "INVALID",
        "ssl_days": ssl_data.get("days_remaining"),
        "final_url": https.get("final_url"),
        "error": https.get("error") or ssl_data.get("error"),
    }


# =========================================================
# HEADER
# =========================================================

st.markdown(
    """
<div class="dc-hero">
    <div class="dc-eyebrow">DOMAIN INTELLIGENCE & WEBSITE HEALTH PLATFORM</div>
    <div class="dc-title">DOMAIN CHECKER PRO</div>
    <div class="dc-subtitle">
        DNS · HTTP/HTTPS · Redirects · SSL/TLS · RDAP · SEO · Email Security ·
        Security Headers · Infrastructure · Bulk Analysis
    </div>
</div>
""",
    unsafe_allow_html=True,
)

st.caption(
    "Public-target protection aktif: localhost, private IP, link-local, reserved IP, "
    "custom ports, dan redirect ke jaringan internal akan ditolak."
)


# =========================================================
# SINGLE SCAN INPUT
# =========================================================

input_col, button_col = st.columns([5, 1])

with input_col:
    domain_input = st.text_input(
        "Target domain",
        placeholder="example.com",
        key="target_domain",
    )

with button_col:
    st.write("")
    st.write("")
    scan_clicked = st.button("Analyze Domain", width="stretch")


if scan_clicked:
    allowed, wait_seconds = check_rate_limit(
        "single_scan_times",
        SINGLE_SCAN_LIMIT,
        SINGLE_SCAN_WINDOW_SECONDS,
    )

    if not allowed:
        st.warning(f"Terlalu banyak scan. Coba lagi sekitar {wait_seconds} detik.")
    else:
        try:
            normalized = normalize_domain(domain_input)
            validate_public_target(normalized)

            report = run_scan(normalized)
            st.session_state["domain_report"] = report
            add_history(report)

        except ValueError as exc:
            st.error(f"Target ditolak: {exc}")
        except Exception as exc:
            st.error(f"Scan gagal: {exc}")


# =========================================================
# TOP LEVEL TABS
# =========================================================

main_tabs = st.tabs(["Single Scan", "Bulk Scan", "History"])

with main_tabs[0]:
    report = st.session_state.get("domain_report")

    if not report:
        st.info("Masukkan domain di atas lalu klik **Analyze Domain**.")
    else:
        st.caption(f'Last analysis: {report["checked_at"]}')

        detail_tabs = st.tabs(
            [
                "Overview",
                "Recommendations",
                "DNS",
                "Email Security",
                "HTTP & Redirects",
                "SSL / TLS",
                "Domain / RDAP",
                "SEO",
                "Security",
                "Export",
            ]
        )

        with detail_tabs[0]:
            render_overview(report)

        with detail_tabs[1]:
            render_recommendations(report)

        with detail_tabs[2]:
            render_dns(report)

        with detail_tabs[3]:
            render_email_security(report)

        with detail_tabs[4]:
            render_http(report)

        with detail_tabs[5]:
            render_ssl(report)

        with detail_tabs[6]:
            render_rdap(report)

        with detail_tabs[7]:
            render_seo(report)

        with detail_tabs[8]:
            render_security(report)

        with detail_tabs[9]:
            safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", report["domain"])
            json_data = json.dumps(report, indent=2, ensure_ascii=False)

            st.download_button(
                "Download JSON Report",
                data=json_data,
                file_name=f"domain_report_{safe_name}.json",
                mime="application/json",
                width="content",
            )

            lines = [
                "DOMAIN CHECKER PRO REPORT",
                f"Domain: {report['domain']}",
                f"Checked: {report['checked_at']}",
                f"Health Score: {report['health']['score']}/100",
                f"Grade: {report['health']['grade']}",
                f"HTTPS: {report['https'].get('status_code')}",
                f"Final URL: {report['https'].get('final_url')}",
                f"Response Time: {report['https'].get('response_time_ms')} ms",
                f"SSL Valid: {report['ssl'].get('valid')}",
                "",
                "ISSUES:",
            ]

            for issue in report["health"]["issues"]:
                lines.append(
                    f"[{issue['severity']}] {issue['title']} - {issue['description']}"
                )

            st.download_button(
                "Download TXT Summary",
                data="\n".join(lines),
                file_name=f"domain_summary_{safe_name}.txt",
                mime="text/plain",
                width="content",
            )


with main_tabs[1]:
    st.subheader("Bulk Domain Checker")
    st.caption(
        f"Maksimal {MAX_BULK_DOMAINS} domain per scan. "
        "Semua target tetap melewati public-target protection."
    )

    bulk_text = st.text_area(
        "Domains",
        placeholder="example.com\ngoogle.com\nopenai.com",
        height=220,
        key="bulk_domains",
    )

    if st.button("Run Bulk Scan", width="content"):
        allowed, wait_seconds = check_rate_limit(
            "bulk_scan_times",
            BULK_SCAN_LIMIT,
            BULK_SCAN_WINDOW_SECONDS,
        )

        if not allowed:
            st.warning(f"Bulk scan terlalu sering. Coba lagi sekitar {wait_seconds} detik.")
        else:
            raw_domains = [line.strip() for line in bulk_text.splitlines() if line.strip()]

            seen = set()
            domains = []

            for d in raw_domains:
                if d not in seen:
                    domains.append(d)
                    seen.add(d)

            domains = domains[:MAX_BULK_DOMAINS]

            if not domains:
                st.warning("Masukkan minimal satu domain.")
            else:
                rows = []
                progress = st.progress(0, text="Starting bulk scan...")

                for idx, domain in enumerate(domains, start=1):
                    progress.progress(
                        idx / len(domains),
                        text=f"Checking {domain} ({idx}/{len(domains)})",
                    )
                    rows.append(bulk_light_scan(domain))

                progress.empty()
                st.session_state["bulk_results"] = rows

    rows = st.session_state.get("bulk_results", [])

    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)

        csv_buf = io.StringIO()
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(csv_buf, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

        st.download_button(
            "Download Bulk Results CSV",
            data=csv_buf.getvalue(),
            file_name="bulk_domain_results.csv",
            mime="text/csv",
            width="content",
        )


with main_tabs[2]:
    history = st.session_state["scan_history"]

    if not history:
        st.info("Belum ada history scan pada sesi browser ini.")
    else:
        st.dataframe(history, width="stretch", hide_index=True)

        csv_buf = io.StringIO()
        writer = csv.DictWriter(csv_buf, fieldnames=history[0].keys())
        writer.writeheader()
        writer.writerows(history)

        st.download_button(
            "Download History CSV",
            data=csv_buf.getvalue(),
            file_name="domain_checker_history.csv",
            mime="text/csv",
            width="content",
        )

        if st.button("Clear Session History", width="content"):
            st.session_state["scan_history"] = []
            st.rerun()

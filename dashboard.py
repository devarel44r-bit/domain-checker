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

PUBLIC_DNS_RESOLVERS = {
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Quad9": ["9.9.9.9", "149.112.112.112"],
}

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
    page_title="Domain Checker Online - Cek DNS, SSL & HTTP",
    page_icon="🌐",
    layout="wide"
)

for key, default in {
    "scan_history": [],
    "domain_report": None,
    "single_scan_times": [],
    "bulk_scan_times": [],
    "bulk_results": [],
    "last_reports_by_domain": {},
    "previous_report": None,
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

    dmarc_policy = None
    if dmarc_txt:
        match = re.search(r"(?:^|;)\s*p\s*=\s*([^;\s]+)", dmarc_txt[0], re.I)
        if match:
            dmarc_policy = match.group(1).lower()

    mx = dns_data.get("MX", [])

    return {
        "spf_present": bool(spf),
        "spf_records": spf,
        "spf_multiple": len(spf) > 1,
        "dmarc_present": bool(dmarc_txt),
        "dmarc_records": dmarc_txt,
        "dmarc_policy": dmarc_policy,
        "mx_present": bool(mx),
        "mx_records": mx,
        "dkim_note": "DKIM membutuhkan selector; tidak bisa dipastikan hanya dari nama domain.",
    }



def resolve_with_nameservers(domain: str, record_type: str, nameservers):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(nameservers)
    resolver.timeout = 3
    resolver.lifetime = 5

    try:
        answers = resolver.resolve(domain, record_type)
        values = []

        for answer in answers:
            if record_type == "MX":
                values.append(f"{int(answer.preference)} {str(answer.exchange).rstrip('.')}")
            else:
                values.append(str(answer).strip('"').rstrip("."))

        return sorted(values)

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []

    except Exception as exc:
        return [f"ERROR: {exc}"]


def check_dns_propagation(domain: str):
    validate_public_target(domain)

    result = {}

    for resolver_name, nameservers in PUBLIC_DNS_RESOLVERS.items():
        result[resolver_name] = {
            "A": resolve_with_nameservers(domain, "A", nameservers),
            "AAAA": resolve_with_nameservers(domain, "AAAA", nameservers),
            "NS": resolve_with_nameservers(domain, "NS", nameservers),
        }

    fingerprints = {}
    for resolver_name, data in result.items():
        fingerprint = json.dumps(
            {
                "A": [x for x in data["A"] if not str(x).startswith("ERROR:")],
                "AAAA": [x for x in data["AAAA"] if not str(x).startswith("ERROR:")],
                "NS": [x for x in data["NS"] if not str(x).startswith("ERROR:")],
            },
            sort_keys=True,
        )
        fingerprints[resolver_name] = fingerprint

    healthy_fingerprints = [
        value
        for name, value in fingerprints.items()
        if not any(
            str(item).startswith("ERROR:")
            for record_values in result[name].values()
            for item in record_values
        )
    ]

    result["_consistent"] = (
        len(set(healthy_fingerprints)) <= 1
        if healthy_fingerprints
        else False
    )

    return result


def diagnose_dns(report):
    dns_data = report["dns"]
    propagation = report.get("dns_propagation", {})
    email = report["email_security"]

    diagnostics = []

    if not dns_data.get("A") and not dns_data.get("AAAA"):
        diagnostics.append({
            "severity": "HIGH",
            "title": "Tidak ada A/AAAA record",
            "description": "Domain tidak memiliki alamat IP yang berhasil ditemukan.",
        })

    if not dns_data.get("NS"):
        diagnostics.append({
            "severity": "HIGH",
            "title": "Nameserver tidak ditemukan",
            "description": "NS record tidak berhasil ditemukan.",
        })

    if dns_data.get("CNAME") and (dns_data.get("A") or dns_data.get("AAAA")):
        diagnostics.append({
            "severity": "MEDIUM",
            "title": "CNAME bersama A/AAAA terdeteksi",
            "description": "Pada hostname yang sama, kombinasi CNAME dengan record lain dapat mengindikasikan konfigurasi DNS yang perlu diperiksa.",
        })

    if not dns_data.get("CAA"):
        diagnostics.append({
            "severity": "LOW",
            "title": "CAA record tidak ditemukan",
            "description": "CAA bersifat opsional, tetapi dapat membatasi CA yang diizinkan menerbitkan sertifikat.",
        })

    if not dns_data.get("dnssec_detected"):
        diagnostics.append({
            "severity": "LOW",
            "title": "DS record DNSSEC tidak terdeteksi",
            "description": "Tool ini hanya mendeteksi keberadaan DS record; ini bukan validasi penuh rantai DNSSEC.",
        })

    if email.get("spf_multiple"):
        diagnostics.append({
            "severity": "MEDIUM",
            "title": "Lebih dari satu SPF record terdeteksi",
            "description": "SPF sebaiknya dipublikasikan sebagai satu policy TXT yang valid.",
        })

    if propagation and not propagation.get("_consistent", False):
        diagnostics.append({
            "severity": "MEDIUM",
            "title": "Hasil DNS resolver publik tidak konsisten",
            "description": "Cloudflare, Google, dan Quad9 memberikan hasil yang berbeda atau salah satu resolver gagal menjawab.",
        })

    return diagnostics


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
        "content_encoding": None,
        "x_robots_tag": None,
        "powered_by": None,
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
        result["content_encoding"] = response.headers.get("Content-Encoding")
        result["x_robots_tag"] = response.headers.get("X-Robots-Tag")
        result["powered_by"] = response.headers.get("X-Powered-By")

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
        "looks_valid": None,
        "validation_note": None,
        "error": None,
    }

    try:
        response, _, final_url = safe_http_get(url)
        result["status"] = response.status_code
        result["final_url"] = final_url
        result["content_type"] = response.headers.get("Content-Type")

        body = response.text[:300_000] if response.content else ""
        path = (urlparse(url).path or "").lower()

        if path.endswith("/robots.txt"):
            looks_valid = bool(
                re.search(r"(?im)^\s*(user-agent|sitemap)\s*:", body)
            )
            result["looks_valid"] = looks_valid
            result["validation_note"] = (
                "robots.txt-like directives detected"
                if looks_valid
                else "HTTP response ada, tetapi directive robots.txt umum tidak terdeteksi"
            )

        elif path.endswith("/sitemap.xml"):
            lower_body = body.lower()
            looks_valid = (
                "<urlset" in lower_body
                or "<sitemapindex" in lower_body
            )
            result["looks_valid"] = looks_valid
            result["validation_note"] = (
                "sitemap XML structure detected"
                if looks_valid
                else "HTTP response ada, tetapi <urlset> / <sitemapindex> tidak terdeteksi"
            )

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
        "san_count": 0,
        "wildcard_certificate": False,
        "hostname_match": False,
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
                result["san_count"] = len(result["san"])
                result["wildcard_certificate"] = any(
                    str(name).startswith("*.")
                    for name in result["san"]
                )
                # create_default_context + server_hostname already validates hostname.
                result["hostname_match"] = True

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



def analyze_redirects(report):
    diagnostics = []
    http_chain = report["http"].get("redirect_chain", [])
    https_chain = report["https"].get("redirect_chain", [])

    for label, chain in [("HTTP", http_chain), ("HTTPS", https_chain)]:
        urls = [hop.get("url") for hop in chain if hop.get("url")]

        if len(chain) > 4:
            diagnostics.append({
                "severity": "LOW",
                "title": f"{label} redirect chain cukup panjang",
                "description": f"Terdeteksi {max(0, len(chain) - 1)} redirect sebelum final response.",
            })

        if len(urls) != len(set(urls)):
            diagnostics.append({
                "severity": "HIGH",
                "title": f"{label} redirect loop terindikasi",
                "description": "URL yang sama muncul lebih dari sekali di redirect chain.",
            })

    http_final = (report["http"].get("final_url") or "").lower()
    if report["http"].get("status_code") is not None and not http_final.startswith("https://"):
        diagnostics.append({
            "severity": "MEDIUM",
            "title": "HTTP tidak berakhir di HTTPS",
            "description": "Pertimbangkan redirect HTTP → HTTPS untuk hostname publik.",
        })

    www_data = report.get("www_check", {})
    www_final = (www_data.get("www", {}).get("final_url") or "").lower()
    root_final = (www_data.get("root", {}).get("final_url") or "").lower()

    if www_final and root_final:
        if urlparse(www_final).hostname != urlparse(root_final).hostname:
            diagnostics.append({
                "severity": "LOW",
                "title": "WWW dan non-WWW berakhir di hostname berbeda",
                "description": f"WWW → {urlparse(www_final).hostname}; non-WWW → {urlparse(root_final).hostname}. Pastikan ini memang canonical behavior yang diinginkan.",
            })

    return diagnostics


def analyze_indexability(report):
    seo = report["https"].get("seo", {})
    headers = report["https"].get("headers", {})
    meta_robots = (seo.get("meta_robots") or "").lower()
    x_robots = (
        report["https"].get("x_robots_tag")
        or headers.get("X-Robots-Tag")
        or headers.get("x-robots-tag")
        or ""
    ).lower()

    noindex_sources = []

    if "noindex" in meta_robots:
        noindex_sources.append("meta robots")

    if "noindex" in x_robots:
        noindex_sources.append("X-Robots-Tag")

    canonical = seo.get("canonical")
    canonical_host = None

    if canonical:
        try:
            canonical_host = urlparse(urljoin(report["https"].get("final_url") or "", canonical)).hostname
        except Exception:
            canonical_host = None

    final_host = urlparse(report["https"].get("final_url") or "").hostname

    return {
        "indexable_signal": not bool(noindex_sources),
        "noindex_sources": noindex_sources,
        "meta_robots": seo.get("meta_robots"),
        "x_robots_tag": report["https"].get("x_robots_tag"),
        "canonical": canonical,
        "canonical_host": canonical_host,
        "canonical_cross_domain": bool(
            canonical_host
            and final_host
            and canonical_host.lower() != final_host.lower()
        ),
    }


def analyze_performance(report):
    https = report["https"]
    response_ms = https.get("response_time_ms")
    response_bytes = https.get("response_bytes")
    encoding = https.get("content_encoding")

    if response_ms is None:
        latency_grade = "Unknown"
    elif response_ms < 500:
        latency_grade = "Fast"
    elif response_ms < 1200:
        latency_grade = "Good"
    elif response_ms < 2500:
        latency_grade = "Slow"
    else:
        latency_grade = "Very Slow"

    if response_bytes is None:
        size_grade = "Unknown"
    elif response_bytes < 500_000:
        size_grade = "Light"
    elif response_bytes < 1_500_000:
        size_grade = "Moderate"
    else:
        size_grade = "Heavy"

    return {
        "response_time_ms": response_ms,
        "latency_grade": latency_grade,
        "response_bytes": response_bytes,
        "size_grade": size_grade,
        "content_encoding": encoding,
        "compression_detected": bool(encoding),
    }


def build_category_scores(report):
    scores = {
        "DNS": 100,
        "HTTP": 100,
        "TLS": 100,
        "Security": 100,
        "SEO": 100,
        "Email": 100,
        "Domain": 100,
    }

    dns = report["dns"]
    propagation = report.get("dns_propagation", {})
    if not dns.get("A") and not dns.get("AAAA"):
        scores["DNS"] -= 50
    if not dns.get("NS"):
        scores["DNS"] -= 30
    if not dns.get("dnssec_detected"):
        scores["DNS"] -= 10
    if propagation and not propagation.get("_consistent", False):
        scores["DNS"] -= 15

    http = report["https"]
    code = http.get("status_code")
    if code is None:
        scores["HTTP"] -= 70
    elif code >= 500:
        scores["HTTP"] -= 40
    elif code >= 400:
        scores["HTTP"] -= 25
    elif code >= 300:
        scores["HTTP"] -= 5

    perf = report.get("performance", {})
    if perf.get("response_time_ms") is not None:
        if perf["response_time_ms"] > 3000:
            scores["HTTP"] -= 20
        elif perf["response_time_ms"] > 1200:
            scores["HTTP"] -= 10

    ssl_data = report["ssl"]
    if not ssl_data.get("valid"):
        scores["TLS"] = 20
    else:
        days = ssl_data.get("days_remaining")
        if days is not None and days < 7:
            scores["TLS"] -= 35
        elif days is not None and days < 30:
            scores["TLS"] -= 15

    missing_security = [
        name
        for name, data in report["security_headers"].items()
        if not data["present"]
    ]
    scores["Security"] -= min(60, len(missing_security) * 10)

    seo = report["https"].get("seo", {})
    if not seo.get("title"):
        scores["SEO"] -= 20
    if not seo.get("meta_description"):
        scores["SEO"] -= 15
    if not seo.get("canonical"):
        scores["SEO"] -= 10
    if seo.get("h1_count", 0) == 0:
        scores["SEO"] -= 10
    if not report["indexability"]["indexable_signal"]:
        scores["SEO"] -= 35
    if report["robots_txt"].get("status") != 200:
        scores["SEO"] -= 5
    if report["sitemap_xml"].get("status") != 200:
        scores["SEO"] -= 5

    email = report["email_security"]
    if email["mx_present"]:
        if not email["spf_present"]:
            scores["Email"] -= 30
        if not email["dmarc_present"]:
            scores["Email"] -= 30
        if email.get("spf_multiple"):
            scores["Email"] -= 15
        if email.get("dmarc_policy") == "none":
            scores["Email"] -= 10
    else:
        scores["Email"] = 100  # No mail service signal; don't punish a web-only domain.

    rdap = report["rdap"]
    if rdap.get("error"):
        scores["Domain"] -= 10
    days = rdap.get("days_to_expiry")
    if days is not None and days < 7:
        scores["Domain"] -= 50
    elif days is not None and days < 30:
        scores["Domain"] -= 25
    elif days is not None and days < 90:
        scores["Domain"] -= 10

    for key in scores:
        scores[key] = max(0, min(100, scores[key]))

    return scores


def build_diagnostics(report):
    diagnostics = []

    diagnostics.extend(diagnose_dns(report))
    diagnostics.extend(analyze_redirects(report))

    indexability = report["indexability"]

    if indexability["noindex_sources"]:
        diagnostics.append({
            "severity": "MEDIUM",
            "title": "Noindex terdeteksi",
            "description": "Sumber: " + ", ".join(indexability["noindex_sources"]),
        })

    if indexability["canonical_cross_domain"]:
        diagnostics.append({
            "severity": "LOW",
            "title": "Canonical mengarah ke domain berbeda",
            "description": f'Canonical host: {indexability["canonical_host"]}. Pastikan ini disengaja.',
        })

    robots = report["robots_txt"]
    if robots.get("status") == 200 and robots.get("looks_valid") is False:
        diagnostics.append({
            "severity": "LOW",
            "title": "robots.txt merespons 200 tetapi formatnya meragukan",
            "description": robots.get("validation_note") or "Directive umum robots.txt tidak terdeteksi.",
        })

    sitemap = report["sitemap_xml"]
    if sitemap.get("status") == 200 and sitemap.get("looks_valid") is False:
        diagnostics.append({
            "severity": "LOW",
            "title": "sitemap.xml merespons 200 tetapi struktur sitemap tidak terdeteksi",
            "description": sitemap.get("validation_note") or "Elemen <urlset> / <sitemapindex> tidak terdeteksi.",
        })

    perf = report["performance"]
    if perf["latency_grade"] in ("Slow", "Very Slow"):
        diagnostics.append({
            "severity": "MEDIUM" if perf["latency_grade"] == "Very Slow" else "LOW",
            "title": f'Latency: {perf["latency_grade"]}',
            "description": f'HTTPS response time: {perf["response_time_ms"]} ms.',
        })

    if perf["size_grade"] == "Heavy":
        diagnostics.append({
            "severity": "LOW",
            "title": "Response homepage cukup besar",
            "description": f'Ukuran response sekitar {perf["response_bytes"]} bytes.',
        })

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    diagnostics.sort(key=lambda item: order.get(item["severity"], 99))

    return diagnostics


def compare_reports(old_report, new_report):
    if not old_report or not new_report:
        return []

    changes = []

    fields = [
        ("HTTPS status", old_report.get("https", {}).get("status_code"), new_report.get("https", {}).get("status_code")),
        ("Final URL", old_report.get("https", {}).get("final_url"), new_report.get("https", {}).get("final_url")),
        ("Primary IPv4", (old_report.get("dns", {}).get("A") or [None])[0], (new_report.get("dns", {}).get("A") or [None])[0]),
        ("Nameservers", old_report.get("dns", {}).get("NS"), new_report.get("dns", {}).get("NS")),
        ("TLS valid", old_report.get("ssl", {}).get("valid"), new_report.get("ssl", {}).get("valid")),
        ("TLS expiry", old_report.get("ssl", {}).get("valid_until"), new_report.get("ssl", {}).get("valid_until")),
        ("Title", old_report.get("https", {}).get("seo", {}).get("title"), new_report.get("https", {}).get("seo", {}).get("title")),
        ("Canonical", old_report.get("https", {}).get("seo", {}).get("canonical"), new_report.get("https", {}).get("seo", {}).get("canonical")),
        ("Health score", old_report.get("health", {}).get("score"), new_report.get("health", {}).get("score")),
    ]

    for label, before, after in fields:
        if before != after:
            changes.append({
                "field": label,
                "before": before,
                "after": after,
            })

    return changes


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

        status.write("Checking DNS propagation across public resolvers...")
        report["dns_propagation"] = check_dns_propagation(domain)

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

        status.write("Analyzing indexability and performance...")
        report["indexability"] = analyze_indexability(report)
        report["performance"] = analyze_performance(report)

        status.write("Calculating health and category scores...")
        report["health"] = build_health(report)
        report["category_scores"] = build_category_scores(report)
        report["diagnostics"] = build_diagnostics(report)

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



def render_category_scores(report):
    scores = report.get("category_scores", {})

    st.subheader("Category Scores")
    st.caption("Skor ini adalah diagnostic heuristic dari data yang diperiksa, bukan sertifikasi keamanan.")

    labels = list(scores.keys())
    cols = st.columns(len(labels))

    for idx, label in enumerate(labels):
        score = scores[label]
        css = "ok" if score >= 80 else "warn" if score >= 55 else "bad"
        with cols[idx]:
            st.markdown(
                card(label, f"{score}/100", css, "Category health"),
                unsafe_allow_html=True,
            )


def render_diagnostics(report):
    diagnostics = report.get("diagnostics", [])

    st.subheader("Deep Diagnostics")
    st.caption("Pemeriksaan konfigurasi dan konsistensi berdasarkan hasil scan pasif.")

    if not diagnostics:
        st.success("Tidak ada diagnostic warning tambahan yang terdeteksi.")
        return

    for item in diagnostics:
        if item["severity"] == "HIGH":
            st.error(f'**HIGH — {item["title"]}**\n\n{item["description"]}')
        elif item["severity"] == "MEDIUM":
            st.warning(f'**MEDIUM — {item["title"]}**\n\n{item["description"]}')
        else:
            st.info(f'**LOW — {item["title"]}**\n\n{item["description"]}')


def render_dns_propagation(report):
    data = report.get("dns_propagation", {})

    st.subheader("DNS Propagation")
    st.caption("Perbandingan jawaban A, AAAA, dan NS dari resolver publik.")

    if data.get("_consistent"):
        st.success("Resolver publik yang berhasil menjawab memberikan hasil yang konsisten.")
    else:
        st.warning("Hasil resolver publik berbeda atau salah satu resolver mengalami error.")

    rows = []
    for resolver_name, values in data.items():
        if resolver_name.startswith("_"):
            continue

        rows.append({
            "Resolver": resolver_name,
            "A": ", ".join(values.get("A", [])) or "-",
            "AAAA": ", ".join(values.get("AAAA", [])) or "-",
            "NS": ", ".join(values.get("NS", [])) or "-",
        })

    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)


def render_performance(report):
    perf = report.get("performance", {})
    https = report["https"]

    st.subheader("Performance & Response")

    cols = st.columns(4)

    with cols[0]:
        latency_class = (
            "ok" if perf.get("latency_grade") in ("Fast", "Good")
            else "warn" if perf.get("latency_grade") == "Slow"
            else "bad" if perf.get("latency_grade") == "Very Slow"
            else "neutral"
        )
        st.markdown(
            card(
                "Latency",
                f'{perf.get("response_time_ms")} ms' if perf.get("response_time_ms") is not None else "-",
                latency_class,
                perf.get("latency_grade", "Unknown"),
            ),
            unsafe_allow_html=True,
        )

    with cols[1]:
        st.markdown(
            card(
                "Response Size",
                f'{perf.get("response_bytes")} B' if perf.get("response_bytes") is not None else "-",
                "neutral",
                perf.get("size_grade", "Unknown"),
            ),
            unsafe_allow_html=True,
        )

    with cols[2]:
        st.markdown(
            card(
                "Compression",
                "Detected" if perf.get("compression_detected") else "Not detected",
                "ok" if perf.get("compression_detected") else "warn",
                fmt(perf.get("content_encoding")),
            ),
            unsafe_allow_html=True,
        )

    with cols[3]:
        st.markdown(
            card(
                "Server",
                fmt(https.get("server")),
                "neutral",
                fmt(https.get("powered_by")),
            ),
            unsafe_allow_html=True,
        )


def render_compare(report):
    previous = st.session_state.get("previous_report")

    st.subheader("Compare With Previous Scan")
    st.caption("Perbandingan berlaku untuk scan sebelumnya dari domain yang sama selama sesi aplikasi.")

    if not previous or previous.get("domain") != report.get("domain"):
        st.info("Belum ada scan sebelumnya untuk domain ini pada sesi sekarang.")
        return

    changes = compare_reports(previous, report)

    if not changes:
        st.success("Tidak ada perubahan pada field utama yang dibandingkan.")
        return

    st.dataframe(changes, width="stretch", hide_index=True)


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
    if data.get("spf_multiple"):
        st.warning("Lebih dari satu SPF record terdeteksi.")

    st.subheader("DMARC")
    st.write("**Policy:**", fmt(data.get("dmarc_policy")))
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
            st.write("**Content-Encoding:**", fmt(data.get("content_encoding")))
            st.write("**X-Powered-By:**", fmt(data.get("powered_by")))
            st.write("**X-Robots-Tag:**", fmt(data.get("x_robots_tag")))
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
        st.write("**Hostname match:**", "Yes" if data.get("hostname_match") else "No")
        st.write("**Wildcard certificate:**", "Yes" if data.get("wildcard_certificate") else "No")
        st.write("**SAN count:**", data.get("san_count", 0))
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
        st.write("**X-Robots-Tag:**", fmt(report["https"].get("x_robots_tag")))
        st.write("**HTML language:**", fmt(seo.get("html_lang")))
        st.write("**H1 count:**", seo.get("h1_count", 0))

    indexability = report.get("indexability", {})
    st.subheader("Indexability Signals")

    if indexability.get("indexable_signal"):
        st.success("No explicit noindex signal detected.")
    else:
        st.warning(
            "Noindex terdeteksi dari: "
            + ", ".join(indexability.get("noindex_sources", []))
        )

    if indexability.get("canonical_cross_domain"):
        st.warning(
            f'Canonical mengarah ke domain lain: {indexability.get("canonical_host")}'
        )

    st.divider()

    for label, data in [("robots.txt", report["robots_txt"]), ("sitemap.xml", report["sitemap_xml"])]:
        st.subheader(label)
        st.write("**Status:**", fmt(data.get("status")))
        st.write("**Final URL:**", fmt(data.get("final_url")))
        st.write("**Looks valid:**", fmt(data.get("looks_valid")))
        st.write("**Validation:**", fmt(data.get("validation_note")))
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



def render_infrastructure(report):
    dns_data = report["dns"]
    https = report["https"]
    cf = report["cloudflare"]
    perf = report.get("performance", {})

    st.subheader("Infrastructure Intelligence")

    c1, c2 = st.columns(2)

    with c1:
        st.write("**IPv4:**")
        st.code(json.dumps(dns_data.get("A", []), indent=2), language="json")
        st.write("**IPv6:**")
        st.code(json.dumps(dns_data.get("AAAA", []), indent=2), language="json")
        st.write("**Nameservers:**")
        st.code(json.dumps(dns_data.get("NS", []), indent=2), language="json")

    with c2:
        st.write("**Server header:**", fmt(https.get("server")))
        st.write("**X-Powered-By:**", fmt(https.get("powered_by")))
        st.write("**Content-Encoding:**", fmt(https.get("content_encoding")))
        st.write("**Compression detected:**", "Yes" if perf.get("compression_detected") else "No")

        if cf["detected"]:
            st.success("Cloudflare detected.")
            for reason in cf["reasons"]:
                st.write("•", reason)
        else:
            st.info("Cloudflare tidak terdeteksi dari indikator DNS/HTTP yang diperiksa.")


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
    <div class="dc-eyebrow">ONLINE DOMAIN INTELLIGENCE & WEBSITE HEALTH PLATFORM</div>
    <div class="dc-title">DOMAIN CHECKER</div>
    <div class="dc-subtitle">
        Cek domain online untuk DNS, IP, HTTP/HTTPS, redirect, SSL/TLS, RDAP, SEO,
        DNSSEC, email security, security headers, infrastructure, DNS propagation,
        diagnostics, compare, dan bulk analysis.
    </div>
</div>
""",
    unsafe_allow_html=True,
)

st.caption(
    "Public-target protection aktif: localhost, private IP, link-local, reserved IP, "
    "custom ports, dan redirect ke jaringan internal akan ditolak."
)

st.header("Domain Checker Online", anchor=False)

st.text(
    "Cek domain online untuk DNS, IP, HTTP/HTTPS, SSL/TLS, redirect, nameserver, "
    "DNSSEC, SEO, dan status website."
)

st.markdown(
    """
**Domain Checker** adalah alat untuk mengecek kondisi teknis sebuah domain dan website
secara langsung. Masukkan nama domain untuk memeriksa DNS, alamat IP, HTTP dan HTTPS,
SSL certificate, redirect, nameserver, DNSSEC, MX, SPF, DMARC, informasi registrasi
domain, SEO dasar, robots.txt, sitemap.xml, security headers, response time,
infrastruktur, dan DNS propagation.

Tool ini membantu mendiagnosis domain yang tidak bisa dibuka, SSL bermasalah,
redirect tidak sesuai, DNS belum propagasi, status HTTP error, atau konfigurasi teknis
website yang perlu diperiksa lebih lanjut.
"""
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

            previous = st.session_state["last_reports_by_domain"].get(normalized)
            report = run_scan(normalized)

            st.session_state["previous_report"] = previous
            st.session_state["domain_report"] = report
            st.session_state["last_reports_by_domain"][normalized] = report
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
                "Diagnostics",
                "Category Scores",
                "Recommendations",
                "DNS",
                "DNS Propagation",
                "Email Security",
                "HTTP & Redirects",
                "Performance",
                "SSL / TLS",
                "Domain / RDAP",
                "SEO & Indexability",
                "Security",
                "Infrastructure",
                "Compare",
                "Export",
            ]
        )

        with detail_tabs[0]:
            render_overview(report)

        with detail_tabs[1]:
            render_diagnostics(report)

        with detail_tabs[2]:
            render_category_scores(report)

        with detail_tabs[3]:
            render_recommendations(report)

        with detail_tabs[4]:
            render_dns(report)

        with detail_tabs[5]:
            render_dns_propagation(report)

        with detail_tabs[6]:
            render_email_security(report)

        with detail_tabs[7]:
            render_http(report)

        with detail_tabs[8]:
            render_performance(report)

        with detail_tabs[9]:
            render_ssl(report)

        with detail_tabs[10]:
            render_rdap(report)

        with detail_tabs[11]:
            render_seo(report)

        with detail_tabs[12]:
            render_security(report)

        with detail_tabs[13]:
            render_infrastructure(report)

        with detail_tabs[14]:
            render_compare(report)

        with detail_tabs[15]:
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
                "DOMAIN CHECKER PRO V6 REPORT",
                f"Domain: {report['domain']}",
                f"Checked: {report['checked_at']}",
                f"Health Score: {report['health']['score']}/100",
                f"Grade: {report['health']['grade']}",
                f"HTTPS: {report['https'].get('status_code')}",
                f"Final URL: {report['https'].get('final_url')}",
                f"Response Time: {report['https'].get('response_time_ms')} ms",
                f"SSL Valid: {report['ssl'].get('valid')}",
                f"DNS Propagation Consistent: {report.get('dns_propagation', {}).get('_consistent')}",
                f"Indexable Signal: {report.get('indexability', {}).get('indexable_signal')}",
                "",
                "CATEGORY SCORES:",
            ]

            for category, score in report.get("category_scores", {}).items():
                lines.append(f"{category}: {score}/100")

            lines.extend(["", "HEALTH ISSUES:"])

            for issue in report["health"]["issues"]:
                lines.append(
                    f"[{issue['severity']}] {issue['title']} - {issue['description']}"
                )

            lines.extend(["", "DEEP DIAGNOSTICS:"])

            for issue in report.get("diagnostics", []):
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

# =========================================================
# SEO CONTENT / HELP
# =========================================================

st.divider()

st.markdown(
    """
## Apa yang Bisa Dicek oleh Domain Checker?

Domain Checker Online ini melakukan pemeriksaan teknis terhadap target domain publik.
Pemeriksaan mencakup **DNS record**, **IPv4/IPv6**, **HTTP/HTTPS status**,
**redirect chain**, **SSL/TLS certificate**, **DNSSEC**, **nameserver**,
**MX/SPF/DMARC**, **RDAP dan masa berlaku domain**, **SEO dan indexability dasar**,
**robots.txt**, **sitemap.xml**, **security headers**, **response time**,
**infrastruktur/CDN**, serta **DNS propagation** melalui beberapa resolver publik.

### Kapan Checker Domain Berguna?

Gunakan checker domain saat website sulit dibuka, setelah mengganti DNS atau nameserver,
ketika ingin mengecek apakah HTTP sudah mengarah ke HTTPS, saat memastikan SSL masih valid,
ketika memeriksa domain sebelum digunakan, atau saat melakukan audit teknis website.
Hasil pemeriksaan menampilkan diagnosis dan rekomendasi agar masalah lebih mudah ditemukan.

### Pemeriksaan Utama

- **DNS Checker:** A, AAAA, CNAME, NS, MX, TXT, CAA, SOA, DS dan DNSSEC.
- **HTTP & HTTPS Checker:** status code, redirect, final URL, response size dan response time.
- **SSL Checker:** validitas sertifikat, TLS version, issuer, SAN dan masa berlaku.
- **Domain Checker:** registrar, umur domain, status RDAP dan tanggal kedaluwarsa.
- **SEO Checker:** title, meta description, canonical, robots, H1, sitemap dan indexability dasar.
- **Email Security:** MX, SPF dan DMARC.
- **Security Header Checker:** HSTS, CSP, X-Frame-Options dan header keamanan lainnya.
- **DNS Propagation:** membandingkan hasil resolver publik untuk melihat perbedaan record DNS.

## FAQ Domain Checker

### Apa itu domain checker?
Domain checker adalah alat untuk memeriksa konfigurasi dan kesehatan teknis sebuah domain,
mulai dari DNS dan IP sampai HTTP, HTTPS, SSL, registrar, SEO, serta keamanan dasar.

### Bagaimana cara cek domain?
Masukkan domain seperti `example.com` pada kolom **Target domain**, lalu klik
**Analyze Domain**. Hasil pemeriksaan akan ditampilkan dalam beberapa tab agar mudah dibaca.

### Apakah checker domain ini bisa mengecek SSL?
Ya. Pemeriksaan SSL/TLS menampilkan validitas sertifikat, versi TLS, issuer,
subject alternative names, tanggal berlaku, tanggal kedaluwarsa, dan sisa hari sertifikat.

### Apakah bisa mengecek DNS domain?
Ya. Tool memeriksa record A, AAAA, CNAME, NS, MX, TXT, CAA, SOA dan DS.
Tersedia juga pemeriksaan DNS propagation dari beberapa resolver publik.

### Apakah bisa mengecek status HTTP 200, 301, 404, atau 500?
Ya. Checker menampilkan status HTTP/HTTPS, final URL, redirect chain,
response time, serta error koneksi jika endpoint tidak dapat diakses.

### Apakah Health Score menjamin domain aman atau ranking Google?
Tidak. Health Score adalah ringkasan dari pemeriksaan teknis yang dilakukan aplikasi ini.
Skor tersebut bukan jaminan keamanan menyeluruh, status index Google, atau peringkat pencarian.
"""
)

st.caption(
    "Domain Checker hanya melakukan pemeriksaan terhadap target publik dan mempertahankan "
    "proteksi terhadap localhost, jaringan private/internal, link-local, reserved IP, "
    "custom port, dan redirect menuju target non-public."
)

# =========================================================
# AUTHORITY / BACKLINK METRICS (ADDED ONLY - EXISTING CODE ABOVE UNCHANGED)
# =========================================================

def _get_streamlit_secret(name):
    try:
        value = st.secrets[name]
        return str(value).strip() if value is not None else None
    except Exception:
        return None


def _secret_is_configured(value):
    """Return False for empty values and common placeholder/example values."""
    if not value:
        return False

    text = str(value).strip()
    upper = text.upper()

    exact_placeholders = {
        "MOZ_ACCESS_ID_LU",
        "MOZ_SECRET_KEY_LU",
        "MAJESTIC_API_KEY_LU",
        "AHREFS_API_KEY_LU",
        "ACCESS_ID_MOZ_ASLI",
        "SECRET_KEY_MOZ_ASLI",
        "API_KEY_MAJESTIC_ASLI",
        "API_KEY_AHREFS_ASLI",
        "ISI_ACCESS_ID_MOZ_ASLI",
        "ISI_SECRET_KEY_MOZ_ASLI",
        "ISI_API_KEY_MAJESTIC_ASLI",
        "ISI_API_KEY_AHREFS_ASLI",
    }

    if upper in exact_placeholders:
        return False

    if upper.startswith(("ISI_", "PASTE_", "YOUR_", "CONTOH_", "EXAMPLE_")):
        return False

    return True


def _authority_metric_value(value):
    if value is None or value == "":
        return "-"
    if isinstance(value, float):
        return round(value, 2)
    return value


def check_moz_authority(domain: str):
    """Optional Moz metrics. Only called when real Moz credentials are configured."""
    result = {
        "domain_authority": None,
        "page_authority": None,
        "spam_score": None,
        "configured": False,
        "error": None,
    }

    access_id = _get_streamlit_secret("MOZ_ACCESS_ID")
    secret_key = _get_streamlit_secret("MOZ_SECRET_KEY")

    if not (_secret_is_configured(access_id) and _secret_is_configured(secret_key)):
        return result

    result["configured"] = True

    try:
        validate_public_target(domain)

        response = requests.post(
            "https://lsapi.seomoz.com/v2/url_metrics",
            auth=(access_id, secret_key),
            json={"targets": [domain]},
            headers={"Accept": "application/json"},
            timeout=TIMEOUT,
        )

        if response.status_code != 200:
            result["error"] = "Moz API belum dapat digunakan dengan credential/plan saat ini."
            return result

        payload = response.json()
        rows = payload.get("results") or []

        if not rows:
            result["error"] = "Moz tidak mengembalikan metrics untuk domain ini."
            return result

        row = rows[0] or {}
        result["domain_authority"] = row.get("domain_authority")
        result["page_authority"] = row.get("page_authority")
        result["spam_score"] = row.get("spam_score")

    except requests.RequestException:
        result["error"] = "Moz API sedang tidak dapat dihubungi."
    except Exception:
        result["error"] = "Moz metrics belum dapat dimuat."

    return result


def check_majestic_authority(domain: str):
    """Optional Majestic metrics. Only called when a real Majestic API key is configured."""
    result = {
        "trust_flow": None,
        "citation_flow": None,
        "tf_cf_ratio": None,
        "referring_domains": None,
        "backlinks": None,
        "status": None,
        "configured": False,
        "error": None,
    }

    api_key = _get_streamlit_secret("MAJESTIC_API_KEY")

    if not _secret_is_configured(api_key):
        return result

    result["configured"] = True

    try:
        validate_public_target(domain)

        response = requests.get(
            "https://api.majestic.com/api/json",
            params={
                "app_api_key": api_key,
                "cmd": "GetIndexItemInfo",
                "items": 1,
                "item0": domain,
                "datasource": "fresh",
            },
            headers={"Accept": "application/json"},
            timeout=TIMEOUT,
        )

        if response.status_code != 200:
            result["error"] = "Majestic API belum dapat digunakan dengan key/plan saat ini."
            return result

        payload = response.json()

        if payload.get("Code") != "OK":
            result["error"] = "Majestic API belum dapat digunakan dengan key/plan saat ini."
            return result

        table = (payload.get("DataTables") or {}).get("Results") or {}
        rows = table.get("Data") or []

        if not rows:
            result["error"] = "Majestic tidak mengembalikan metrics untuk domain ini."
            return result

        row = rows[0] or {}
        tf = row.get("TrustFlow")
        cf = row.get("CitationFlow")

        result["trust_flow"] = tf
        result["citation_flow"] = cf
        result["referring_domains"] = row.get("RefDomains")
        result["backlinks"] = row.get("ExtBackLinks")
        result["status"] = row.get("Status")

        try:
            if cf is not None and float(cf) != 0 and tf is not None:
                result["tf_cf_ratio"] = round(float(tf) / float(cf), 3)
        except (TypeError, ValueError, ZeroDivisionError):
            result["tf_cf_ratio"] = None

    except requests.RequestException:
        result["error"] = "Majestic API sedang tidak dapat dihubungi."
    except Exception:
        result["error"] = "Majestic metrics belum dapat dimuat."

    return result


def check_ahrefs_authority(domain: str):
    """
    Ahrefs Public API v3.
    Public API key provides Domain Rating (DR). UR, Referring Domains and
    Backlinks require API access to additional Ahrefs endpoints/plans.
    """
    result = {
        "domain_rating": None,
        "url_rating": None,
        "referring_domains": None,
        "backlinks": None,
        "configured": False,
        "error": None,
    }

    api_key = _get_streamlit_secret("AHREFS_API_KEY")

    if not _secret_is_configured(api_key):
        return result

    result["configured"] = True

    try:
        validate_public_target(domain)

        response = requests.get(
            "https://api.ahrefs.com/v3/public/domain-rating-free",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
            params={"target": domain, "output": "json"},
            timeout=TIMEOUT,
        )

        if response.status_code != 200:
            result["error"] = "Ahrefs Public API key belum dapat digunakan. Periksa key di Streamlit Secrets."
            return result

        payload = response.json()
        dr_block = payload.get("domain_rating") or {}

        if isinstance(dr_block, dict):
            result["domain_rating"] = dr_block.get("domain_rating")
        else:
            result["domain_rating"] = dr_block

        if result["domain_rating"] is None:
            result["error"] = "Ahrefs tidak mengembalikan Domain Rating untuk target ini."

    except requests.RequestException:
        result["error"] = "Ahrefs Public API sedang tidak dapat dihubungi."
    except Exception:
        result["error"] = "Ahrefs DR belum dapat dimuat."

    return result


def check_authority_metrics(domain: str):
    validate_public_target(domain)

    return {
        "domain": domain,
        "moz": check_moz_authority(domain),
        "majestic": check_majestic_authority(domain),
        "ahrefs": check_ahrefs_authority(domain),
    }


st.divider()
st.subheader("Authority & Backlink Metrics")
st.caption(
    "Authority metrics tambahan. Ahrefs DR dapat memakai Public API key. "
    "Moz dan Majestic hanya aktif jika API provider terkait sudah tersedia."
)

authority_domain_input = st.text_input(
    "Domain untuk Authority Metrics",
    value=(domain_input or "").strip(),
    placeholder="example.com",
    key="authority_domain_input",
)

if st.button("Check Authority Metrics", width="content"):
    try:
        authority_domain = normalize_domain(authority_domain_input)
        validate_public_target(authority_domain)

        with st.spinner("Mengambil authority metrics..."):
            st.session_state["authority_metrics_result"] = check_authority_metrics(authority_domain)

    except ValueError as exc:
        st.error(f"Target ditolak: {exc}")
    except Exception as exc:
        st.error(f"Authority metrics gagal: {exc}")


authority_result = st.session_state.get("authority_metrics_result")

if authority_result:
    st.caption(f"Authority metrics untuk: {authority_result.get('domain', '-')}")

    moz_data = authority_result.get("moz", {})
    majestic_data = authority_result.get("majestic", {})
    ahrefs_data = authority_result.get("ahrefs", {})

    moz_tab, majestic_tab, ahrefs_tab = st.tabs(["Moz", "Majestic", "Ahrefs"])

    with moz_tab:
        cols = st.columns(3)
        cols[0].metric("Moz DA", _authority_metric_value(moz_data.get("domain_authority")))
        cols[1].metric("Moz PA", _authority_metric_value(moz_data.get("page_authority")))
        cols[2].metric("Moz Spam Score", _authority_metric_value(moz_data.get("spam_score")))

        if not moz_data.get("configured"):
            st.info("Moz belum aktif. DA, PA, dan Spam Score membutuhkan Moz API credentials yang valid.")
        elif moz_data.get("error"):
            st.info(moz_data["error"])

    with majestic_tab:
        cols = st.columns(5)
        cols[0].metric("Majestic TF", _authority_metric_value(majestic_data.get("trust_flow")))
        cols[1].metric("Majestic CF", _authority_metric_value(majestic_data.get("citation_flow")))
        cols[2].metric("TF/CF Ratio", _authority_metric_value(majestic_data.get("tf_cf_ratio")))
        cols[3].metric("Referring Domains", _authority_metric_value(majestic_data.get("referring_domains")))
        cols[4].metric("Backlinks", _authority_metric_value(majestic_data.get("backlinks")))

        if not majestic_data.get("configured"):
            st.info("Majestic belum aktif. TF, CF, Referring Domains, dan Backlinks membutuhkan Majestic API plan/key.")
        elif majestic_data.get("error"):
            st.info(majestic_data["error"])

    with ahrefs_tab:
        cols = st.columns(4)
        cols[0].metric("Ahrefs DR", _authority_metric_value(ahrefs_data.get("domain_rating")))
        cols[1].metric("Ahrefs UR", "-")
        cols[2].metric("Referring Domains", "-")
        cols[3].metric("Backlinks", "-")

        if not ahrefs_data.get("configured"):
            st.info("Ahrefs DR belum aktif. Tambahkan AHREFS_API_KEY Public API di Streamlit Secrets.")
        elif ahrefs_data.get("error"):
            st.info(ahrefs_data["error"])
        else:
            st.success("Ahrefs Public API terhubung. Domain Rating (DR) aktif.")

        st.caption(
            "Ahrefs UR, Referring Domains, dan Backlinks tidak tersedia melalui Public DR endpoint; "
            "metric tersebut membutuhkan akses API Ahrefs yang sesuai."
        )

    st.caption(
        "Moz, Majestic, dan Ahrefs adalah metric milik provider masing-masing. "
        "Tidak ada nilai authority yang dibuat atau diperkirakan oleh aplikasi ini."
    )

# =========================================================
# NAWALA / INDONESIA BLOCK CHECK (ADDED ONLY - EXISTING CODE ABOVE UNCHANGED)
# =========================================================

def _nawala_api_key_configured(value):
    """Return False for empty/example Nawala API key values."""
    if not value:
        return False

    text = str(value).strip()
    upper = text.upper()

    if upper in {
        "NAWALA_API_KEY_LU",
        "API_KEY_NAWALA_ASLI",
        "ISI_API_KEY_NAWALA_ASLI",
        "NAWALA_API_KEY_ANDA",
    }:
        return False

    if upper.startswith(("ISI_", "PASTE_", "YOUR_", "CONTOH_", "EXAMPLE_")):
        return False

    return True


def check_nawala_status(domain: str):
    """
    Check Indonesia block/access status through the NawalaCheck third-party API.

    This does not modify or bypass any blocking system. It only reports the
    status returned by the external provider for a public domain.
    """
    result = {
        "domain": domain,
        "blocked": None,
        "status": "UNKNOWN",
        "configured": False,
        "provider": "NawalaCheck",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "http_status": None,
        "error": None,
    }

    api_key = _get_streamlit_secret("NAWALA_API_KEY")

    if not _nawala_api_key_configured(api_key):
        return result

    result["configured"] = True

    try:
        validate_public_target(domain)

        response = requests.get(
            "https://nawalacheck.com/api",
            params={"domain": domain},
            headers={
                "X-API-Key": api_key,
                "Accept": "application/json",
            },
            timeout=TIMEOUT,
        )

        result["http_status"] = response.status_code

        if response.status_code != 200:
            if response.status_code in (401, 403):
                result["error"] = (
                    "NawalaCheck menolak API key/request. Periksa NAWALA_API_KEY, "
                    "status akun, limit, atau pengaturan akses provider."
                )
            elif response.status_code == 429:
                result["error"] = "Limit request NawalaCheck tercapai. Coba lagi setelah limit provider reset."
            else:
                result["error"] = f"NawalaCheck API HTTP {response.status_code}."
            return result

        try:
            payload = response.json()
        except ValueError:
            result["error"] = "Respons NawalaCheck bukan JSON yang valid."
            return result

        domain_key = domain.lower().rstrip(".")
        row = None

        if isinstance(payload, dict):
            row = payload.get(domain_key) or payload.get(domain)

            if row is None:
                # Be tolerant if the provider normalizes the returned key.
                for key, value in payload.items():
                    if str(key).lower().rstrip(".") == domain_key:
                        row = value
                        break

        if not isinstance(row, dict):
            result["error"] = "NawalaCheck tidak mengembalikan status domain yang dapat dibaca."
            return result

        blocked = row.get("blocked")

        if isinstance(blocked, bool):
            result["blocked"] = blocked
        elif isinstance(blocked, (int, float)) and blocked in (0, 1):
            result["blocked"] = bool(blocked)
        elif isinstance(blocked, str):
            normalized = blocked.strip().lower()
            if normalized in {"true", "1", "yes", "blocked", "blokir", "diblokir"}:
                result["blocked"] = True
            elif normalized in {"false", "0", "no", "safe", "clear", "aman", "unblocked"}:
                result["blocked"] = False

        if result["blocked"] is True:
            result["status"] = "DIBLOKIR"
        elif result["blocked"] is False:
            result["status"] = "AMAN"
        else:
            result["status"] = "UNKNOWN"
            result["error"] = "Field status blokir tidak ditemukan pada respons provider."

    except requests.Timeout:
        result["error"] = "NawalaCheck timeout. Provider tidak menjawab dalam batas waktu."
    except requests.RequestException:
        result["error"] = "NawalaCheck sedang tidak dapat dihubungi."
    except Exception as exc:
        result["error"] = f"Status Nawala belum dapat dimuat: {exc}"

    return result


st.divider()
st.subheader("Nawala / Indonesia Block Check")
st.caption(
    "Cek status akses/blokir domain di Indonesia melalui NawalaCheck. "
    "NawalaCheck adalah provider pihak ketiga, bukan API resmi Komdigi."
)

nawala_domain_input = st.text_input(
    "Domain untuk Nawala Check",
    value=(domain_input or "").strip(),
    placeholder="example.com",
    key="nawala_domain_input",
)

if st.button("Check Nawala Status", width="content"):
    try:
        nawala_domain = normalize_domain(nawala_domain_input)
        validate_public_target(nawala_domain)

        with st.spinner("Mengecek status Nawala / akses Indonesia..."):
            st.session_state["nawala_check_result"] = check_nawala_status(nawala_domain)

    except ValueError as exc:
        st.error(f"Target ditolak: {exc}")
    except Exception as exc:
        st.error(f"Nawala check gagal: {exc}")


nawala_result = st.session_state.get("nawala_check_result")

if nawala_result:
    st.caption(f"Nawala check untuk: {nawala_result.get('domain', '-')}")

    blocked = nawala_result.get("blocked")
    status_text = nawala_result.get("status", "UNKNOWN")

    if blocked is True:
        status_help = "Provider melaporkan domain terblokir."
    elif blocked is False:
        status_help = "Provider tidak melaporkan domain sebagai terblokir."
    else:
        status_help = "Status belum dapat dipastikan."

    cols = st.columns(4)
    cols[0].metric("Indonesia Block Status", status_text, help=status_help)
    cols[1].metric("Blocked", "YES" if blocked is True else "NO" if blocked is False else "-")
    cols[2].metric("Provider", nawala_result.get("provider", "NawalaCheck"))
    cols[3].metric("API HTTP", nawala_result.get("http_status") or "-")

    if not nawala_result.get("configured"):
        st.info(
            "Nawala Check belum aktif. Tambahkan NAWALA_API_KEY yang valid di Streamlit Secrets."
        )
    elif nawala_result.get("error"):
        st.warning(nawala_result["error"])
    elif blocked is True:
        st.error("Provider melaporkan domain ini sebagai DIBLOKIR pada pengecekan akses Indonesia.")
    elif blocked is False:
        st.success("Provider tidak melaporkan domain ini sebagai terblokir pada pengecekan saat ini.")

    st.caption(
        "Hasil ini mengikuti respons NawalaCheck pada waktu pengecekan dan bukan keputusan resmi hukum/regulator. "
        "Gunakan sebagai sinyal monitoring tambahan, bukan satu-satunya dasar keputusan."
    )

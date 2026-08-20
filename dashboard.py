import socket
import ssl
import json
import re
import html as html_lib
from datetime import datetime, timezone
from urllib.parse import urlparse
from html.parser import HTMLParser

import requests
import streamlit as st
import dns.resolver
import dns.exception


# =========================================================
# CONFIG
# =========================================================

APP_NAME = "Domain Checker"
TIMEOUT = 10

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151 Safari/537.36 DomainChecker/3.0"
)

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

st.set_page_config(
    page_title=APP_NAME,
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# =========================================================
# PROFESSIONAL UI
# =========================================================

st.markdown(
    """
<style>
:root {
    --bg: #080c12;
    --panel: #0d141d;
    --panel-2: #101923;
    --border: #1f2b38;
    --border-2: #263748;
    --text: #edf3f9;
    --muted: #8091a4;
    --muted-2: #65768a;
    --accent: #3c8dbc;
    --accent-2: #56a9d3;
    --ok: #4fc38a;
    --warn: #d7a84e;
    --bad: #df6b74;
}

html, body, [class*="css"] {
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

.stApp {
    color: var(--text);
    background:
        radial-gradient(circle at 15% 0%, rgba(48, 113, 151, .12), transparent 28%),
        radial-gradient(circle at 90% 10%, rgba(30, 78, 110, .08), transparent 24%),
        var(--bg);
}

.block-container {
    max-width: 1450px;
    padding-top: 1.6rem;
    padding-bottom: 4rem;
}

header[data-testid="stHeader"] {
    background: transparent;
}

/* HERO */
.dc-hero {
    background:
        linear-gradient(135deg, rgba(18, 29, 41, .98), rgba(10, 16, 24, .98));
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 28px 30px;
    margin-bottom: 22px;
    box-shadow: 0 14px 34px rgba(0,0,0,.22);
}

.dc-eyebrow {
    color: #6e8297;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1.7px;
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

/* INPUT */
.stTextInput label {
    color: #a9b6c4 !important;
    font-weight: 600 !important;
    font-size: 13px !important;
}

.stTextInput input {
    background: #0c131c !important;
    color: #e7eef6 !important;
    border: 1px solid var(--border-2) !important;
    border-radius: 9px !important;
    padding: 12px 14px !important;
    font-family: "Cascadia Code", Consolas, monospace !important;
}

.stTextInput input:focus {
    border-color: #448db8 !important;
    box-shadow: 0 0 0 1px #448db8 !important;
}

/* BUTTONS */
.stButton button,
.stDownloadButton button {
    background: #176f9f !important;
    color: #ffffff !important;
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

/* METRIC CARDS */
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
    letter-spacing: 1.15px;
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

/* STATUS */
.ok { color: var(--ok); }
.warn { color: var(--warn); }
.bad { color: var(--bad); }
.neutral { color: #dce5ee; }

/* PANELS */
.dc-panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 18px 20px;
    margin-bottom: 16px;
}

.dc-section-title {
    color: #e8eef5;
    font-size: 17px;
    font-weight: 680;
    margin-bottom: 2px;
}

.dc-section-sub {
    color: #718398;
    font-size: 12px;
    margin-bottom: 14px;
}

/* CODE */
code, pre {
    font-family: "Cascadia Code", Consolas, monospace !important;
}

div[data-testid="stCodeBlock"] {
    border: 1px solid #1e2a36;
    border-radius: 9px;
}

/* TABS */
button[data-baseweb="tab"] {
    color: #8394a6 !important;
    font-weight: 650 !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #dceaf4 !important;
}

/* TABLE */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border);
    border-radius: 9px;
    overflow: hidden;
}

/* EXPANDER */
details {
    border-color: var(--border) !important;
}

/* Hide Streamlit decoration */
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }

hr {
    border: none;
    border-top: 1px solid var(--border);
}
</style>
""",
    unsafe_allow_html=True,
)


# =========================================================
# HELPERS
# =========================================================

def normalize_domain(value: str) -> str:
    value = value.strip()

    if not value:
        raise ValueError("Domain belum diisi.")

    if "://" not in value:
        value = "https://" + value

    parsed = urlparse(value)
    host = parsed.hostname or ""

    if not host:
        raise ValueError("Format domain tidak valid.")

    host = host.rstrip(".").lower()

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass

    return host


def fmt(value, fallback="-"):
    if value is None or value == "":
        return fallback
    return value


def safe_html(value):
    return html_lib.escape(str(value))


def status_class(ok=None, warning=False):
    if warning:
        return "warn"
    if ok is True:
        return "ok"
    if ok is False:
        return "bad"
    return "neutral"


def card(label, value, css_class="neutral", sub=None):
    sub_html = (
        f'<div class="dc-card-sub">{safe_html(sub)}</div>'
        if sub
        else ""
    )

    return f"""
    <div class="dc-card">
        <div class="dc-card-label">{safe_html(label)}</div>
        <div class="dc-card-value {css_class}">{safe_html(value)}</div>
        {sub_html}
    </div>
    """


# =========================================================
# HTML PARSER
# =========================================================

class BasicSEOParser(HTMLParser):
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

            if isinstance(rel, str):
                rel_values = rel.lower().split()
            else:
                rel_values = [str(x).lower() for x in rel]

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
        desc = (
            re.sub(r"\s+", " ", self.meta_description).strip()
            if self.meta_description
            else None
        )

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
        answers = dns.resolver.resolve(
            domain,
            record_type,
            lifetime=TIMEOUT
        )

        values = []

        for answer in answers:
            if record_type == "MX":
                values.append({
                    "priority": int(answer.preference),
                    "host": str(answer.exchange).rstrip(".")
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
                values.append(
                    str(answer).strip('"').rstrip(".")
                )

        return values

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []

    except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        return [{"error": str(exc)}]

    except Exception as exc:
        return [{"error": str(exc)}]


def check_dns(domain: str):
    types = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "CAA", "SOA", "DS"]

    data = {}

    for rtype in types:
        data[rtype] = safe_dns_resolve(domain, rtype)

    ds = data.get("DS", [])
    data["dnssec_detected"] = bool(
        ds and not (
            isinstance(ds[0], dict)
            and "error" in ds[0]
        )
    )

    return data


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
        "content_length": None,
        "headers": {},
        "seo": {},
        "error": None,
    }

    try:
        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["response_time_ms"] = round(
            response.elapsed.total_seconds() * 1000,
            2
        )

        result["server"] = response.headers.get("Server")
        result["content_type"] = response.headers.get("Content-Type")
        result["content_length"] = response.headers.get("Content-Length")
        result["headers"] = dict(response.headers)

        for item in response.history:
            result["redirect_chain"].append({
                "status": item.status_code,
                "url": item.url,
                "location": item.headers.get("Location"),
            })

        result["redirect_chain"].append({
            "status": response.status_code,
            "url": response.url,
            "location": None,
        })

        content_type = (
            response.headers.get("Content-Type") or ""
        ).lower()

        if "text/html" in content_type:
            parser = BasicSEOParser()

            try:
                parser.feed(response.text[:2_000_000])
                result["seo"] = parser.result()
            except Exception:
                result["seo"] = {}

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
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=TIMEOUT
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as ssock:

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

                result["subject"] = dict(
                    x[0] for x in cert.get("subject", [])
                )

                result["issuer"] = dict(
                    x[0] for x in cert.get("issuer", [])
                )

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
                    result["days_remaining"] = (
                        expiry - datetime.now(timezone.utc)
                    ).days

                result["san"] = [
                    value
                    for key, value in cert.get(
                        "subjectAltName",
                        []
                    )
                    if key == "DNS"
                ]

    except ssl.SSLCertVerificationError as exc:
        result["error"] = (
            f"Certificate verification failed: {exc}"
        )

    except socket.timeout:
        result["error"] = "SSL connection timeout."

    except Exception as exc:
        result["error"] = str(exc)

    return result


# =========================================================
# RDAP
# =========================================================

def get_vcard_value(vcard_array, key):
    try:
        entries = vcard_array[1]

        for item in entries:
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
        "error": None,
    }

    try:
        response = session.get(
            f"https://rdap.org/domain/{domain}",
            timeout=TIMEOUT,
            allow_redirects=True,
        )

        if response.status_code != 200:
            result["error"] = (
                f"RDAP HTTP {response.status_code}"
            )
            return result

        data = response.json()

        result["handle"] = data.get("handle")
        result["statuses"] = data.get("status", [])

        for ns in data.get("nameservers", []):
            name = (
                ns.get("ldhName")
                or ns.get("unicodeName")
            )

            if name:
                result["nameservers"].append(
                    name.lower()
                )

        for event in data.get("events", []):
            action = event.get("eventAction")
            date = event.get("eventDate")

            if action == "registration":
                result["created"] = date

            elif action == "expiration":
                result["expires"] = date

            elif action in (
                "last changed",
                "last update of RDAP database",
            ):
                if not result["updated"]:
                    result["updated"] = date

        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                result["registrar"] = get_vcard_value(
                    entity.get("vcardArray"),
                    "fn",
                )

                if not result["registrar"]:
                    result["registrar"] = entity.get(
                        "handle"
                    )

                break

    except Exception as exc:
        result["error"] = str(exc)

    return result


# =========================================================
# RESOURCES / SECURITY
# =========================================================

def check_resource(url: str):
    result = {
        "url": url,
        "status": None,
        "final_url": None,
        "content_type": None,
        "error": None,
    }

    try:
        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
        )

        result["status"] = response.status_code
        result["final_url"] = response.url
        result["content_type"] = response.headers.get(
            "Content-Type"
        )

    except requests.RequestException as exc:
        result["error"] = str(exc)

    return result


def security_headers(headers):
    wanted = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "X-Frame-Options",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy",
    }

    lower = {
        k.lower(): v
        for k, v in headers.items()
    }

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

    if any(
        "cloudflare.com" in str(ns).lower()
        for ns in ns_values
    ):
        reasons.append("Cloudflare nameserver")

    headers = https_data.get("headers", {})

    lower = {
        k.lower(): str(v).lower()
        for k, v in headers.items()
    }

    if "cf-ray" in lower:
        reasons.append("CF-RAY response header")

    if "cloudflare" in lower.get("server", ""):
        reasons.append("Cloudflare Server header")

    return {
        "detected": bool(reasons),
        "reasons": reasons,
    }


# =========================================================
# SCAN
# =========================================================

def run_scan(domain: str):
    report = {
        "domain": domain,
        "checked_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    with st.status(
        "Running domain analysis...",
        expanded=True
    ) as status:

        status.write("Resolving DNS records...")
        report["dns"] = check_dns(domain)

        status.write("Checking HTTP endpoint...")
        report["http"] = check_http(
            f"http://{domain}"
        )

        status.write("Checking HTTPS endpoint...")
        report["https"] = check_http(
            f"https://{domain}"
        )

        status.write("Inspecting SSL/TLS certificate...")
        report["ssl"] = check_ssl(domain)

        status.write("Retrieving registration data...")
        report["rdap"] = check_rdap(domain)

        status.write("Checking robots.txt and sitemap.xml...")
        report["robots_txt"] = check_resource(
            f"https://{domain}/robots.txt"
        )

        report["sitemap_xml"] = check_resource(
            f"https://{domain}/sitemap.xml"
        )

        status.write("Checking WWW / non-WWW behavior...")

        www_domain = (
            domain
            if domain.startswith("www.")
            else f"www.{domain}"
        )

        root_domain = (
            domain[4:]
            if domain.startswith("www.")
            else domain
        )

        report["www_check"] = {
            "www": check_http(
                f"https://{www_domain}"
            ),
            "root": check_http(
                f"https://{root_domain}"
            ),
        }

        report["security_headers"] = security_headers(
            report["https"].get(
                "headers",
                {}
            )
        )

        report["cloudflare"] = detect_cloudflare(
            report["dns"],
            report["https"],
        )

        status.update(
            label="Analysis complete",
            state="complete",
            expanded=False,
        )

    return report


# =========================================================
# RENDER
# =========================================================

def render_overview(report):
    domain = report["domain"]
    dns_data = report["dns"]
    https_data = report["https"]
    ssl_data = report["ssl"]
    cloudflare = report["cloudflare"]

    dns_ok = bool(
        dns_data.get("A")
        or dns_data.get("AAAA")
    )

    https_code = https_data.get(
        "status_code"
    )

    https_ok = (
        https_code is not None
        and 200 <= https_code < 400
    )

    ssl_ok = ssl_data.get(
        "valid",
        False
    )

    response_ms = https_data.get(
        "response_time_ms"
    )

    cols = st.columns(5)

    with cols[0]:
        st.markdown(
            card(
                "Domain",
                domain,
                "neutral",
                "Scan target",
            ),
            unsafe_allow_html=True,
        )

    with cols[1]:
        st.markdown(
            card(
                "DNS",
                "Healthy" if dns_ok else "Problem",
                status_class(dns_ok),
                "A / AAAA resolution",
            ),
            unsafe_allow_html=True,
        )

    with cols[2]:
        st.markdown(
            card(
                "HTTPS",
                str(https_code)
                if https_code is not None
                else "Error",
                status_class(https_ok),
                "HTTP response code",
            ),
            unsafe_allow_html=True,
        )

    with cols[3]:
        st.markdown(
            card(
                "TLS Certificate",
                "Valid" if ssl_ok else "Invalid",
                status_class(ssl_ok),
                fmt(
                    ssl_data.get(
                        "tls_version"
                    )
                ),
            ),
            unsafe_allow_html=True,
        )

    with cols[4]:
        st.markdown(
            card(
                "Response Time",
                (
                    f"{response_ms} ms"
                    if response_ms is not None
                    else "-"
                ),
                (
                    "ok"
                    if response_ms is not None
                    and response_ms < 800
                    else "warn"
                    if response_ms is not None
                    else "neutral"
                ),
                (
                    "Cloudflare detected"
                    if cloudflare["detected"]
                    else "Direct / other CDN"
                ),
            ),
            unsafe_allow_html=True,
        )

    st.markdown("")

    left, right = st.columns(
        [1.1, .9]
    )

    with left:
        st.markdown(
            """
            <div class="dc-panel">
                <div class="dc-section-title">Endpoint Summary</div>
                <div class="dc-section-sub">
                    Primary network and application response information
                </div>
            """,
            unsafe_allow_html=True,
        )

        st.write(
            "**Final URL:**",
            fmt(
                https_data.get(
                    "final_url"
                )
            )
        )

        st.write(
            "**Server:**",
            fmt(
                https_data.get(
                    "server"
                )
            )
        )

        st.write(
            "**Content-Type:**",
            fmt(
                https_data.get(
                    "content_type"
                )
            )
        )

        st.write(
            "**Primary IPv4:**",
            (
                dns_data.get("A", ["-"])[0]
                if dns_data.get("A")
                else "-"
            )
        )

        st.write(
            "**Primary Nameserver:**",
            (
                dns_data.get("NS", ["-"])[0]
                if dns_data.get("NS")
                else "-"
            )
        )

        st.markdown(
            "</div>",
            unsafe_allow_html=True,
        )

    with right:
        st.markdown(
            """
            <div class="dc-panel">
                <div class="dc-section-title">Infrastructure Detection</div>
                <div class="dc-section-sub">
                    CDN and edge-network indicators
                </div>
            """,
            unsafe_allow_html=True,
        )

        if cloudflare["detected"]:
            st.success("Cloudflare detected")

            for reason in cloudflare[
                "reasons"
            ]:
                st.write(
                    f"• {reason}"
                )
        else:
            st.info(
                "Cloudflare was not detected from "
                "the DNS and response indicators checked."
            )

        st.markdown(
            "</div>",
            unsafe_allow_html=True,
        )


def render_dns(report):
    dns_data = report["dns"]

    st.markdown(
        """
        <div class="dc-panel">
            <div class="dc-section-title">DNS Intelligence</div>
            <div class="dc-section-sub">
                DNS records resolved from the target domain
            </div>
        """,
        unsafe_allow_html=True,
    )

    for rtype in [
        "A",
        "AAAA",
        "CNAME",
        "NS",
        "MX",
        "TXT",
        "CAA",
        "SOA",
        "DS",
    ]:
        st.markdown(
            f"#### {rtype}"
        )

        value = dns_data.get(
            rtype,
            []
        )

        if value:
            st.code(
                json.dumps(
                    value,
                    indent=2,
                    ensure_ascii=False,
                ),
                language="json",
            )
        else:
            st.caption(
                "No record returned."
            )

    st.write(
        "**DNSSEC DS record detected:**",
        (
            "Yes"
            if dns_data.get(
                "dnssec_detected"
            )
            else "No"
        ),
    )

    st.markdown(
        "</div>",
        unsafe_allow_html=True,
    )


def render_http(report):
    http_data = report["http"]
    https_data = report["https"]
    www_data = report["www_check"]

    c1, c2 = st.columns(2)

    for col, label, data in [
        (
            c1,
            "HTTP",
            http_data,
        ),
        (
            c2,
            "HTTPS",
            https_data,
        ),
    ]:
        with col:
            st.markdown(
                f"""
                <div class="dc-panel">
                    <div class="dc-section-title">{label}</div>
                    <div class="dc-section-sub">
                        Endpoint response and redirect behavior
                    </div>
                """,
                unsafe_allow_html=True,
            )

            st.write(
                "**Status:**",
                fmt(
                    data.get(
                        "status_code"
                    )
                )
            )

            st.write(
                "**Final URL:**",
                fmt(
                    data.get(
                        "final_url"
                    )
                )
            )

            st.write(
                "**Response time:**",
                (
                    f'{data["response_time_ms"]} ms'
                    if data.get(
                        "response_time_ms"
                    ) is not None
                    else "-"
                )
            )

            st.write(
                "**Server:**",
                fmt(
                    data.get(
                        "server"
                    )
                )
            )

            if data.get("error"):
                st.error(
                    data["error"]
                )

            st.markdown(
                "</div>",
                unsafe_allow_html=True,
            )

    st.subheader(
        "Redirect Chain"
    )

    for label, data in [
        (
            "HTTP",
            http_data,
        ),
        (
            "HTTPS",
            https_data,
        ),
    ]:
        with st.expander(
            f"{label} redirects",
            expanded=True
        ):
            chain = data.get(
                "redirect_chain",
                []
            )

            if not chain:
                st.caption(
                    "No redirect chain available."
                )

            for hop in chain:
                st.code(
                    f'{hop["status"]}  {hop["url"]}',
                    language="text",
                )

    st.subheader(
        "WWW vs Non-WWW"
    )

    for label, data in [
        (
            "WWW",
            www_data["www"],
        ),
        (
            "NON-WWW",
            www_data["root"],
        ),
    ]:
        st.write(
            f"**{label}:**",
            (
                f'{data.get("status_code")} → '
                f'{data.get("final_url")}'
                if data.get(
                    "status_code"
                ) is not None
                else fmt(
                    data.get(
                        "error"
                    )
                )
            )
        )


def render_ssl(report):
    ssl_data = report["ssl"]

    if ssl_data.get("valid"):
        st.success(
            "TLS certificate validation succeeded."
        )
    else:
        st.error(
            "TLS certificate validation failed."
        )

    left, right = st.columns(2)

    with left:
        st.write(
            "**TLS version:**",
            fmt(
                ssl_data.get(
                    "tls_version"
                )
            )
        )

        st.write(
            "**Valid from:**",
            fmt(
                ssl_data.get(
                    "valid_from"
                )
            )
        )

        st.write(
            "**Valid until:**",
            fmt(
                ssl_data.get(
                    "valid_until"
                )
            )
        )

        st.write(
            "**Days remaining:**",
            fmt(
                ssl_data.get(
                    "days_remaining"
                )
            )
        )

        st.write(
            "**Serial number:**",
            fmt(
                ssl_data.get(
                    "serial_number"
                )
            )
        )

    with right:
        st.write(
            "**Subject**"
        )

        st.code(
            json.dumps(
                ssl_data.get(
                    "subject",
                    {}
                ),
                indent=2,
                ensure_ascii=False,
            ),
            language="json",
        )

        st.write(
            "**Issuer**"
        )

        st.code(
            json.dumps(
                ssl_data.get(
                    "issuer",
                    {}
                ),
                indent=2,
                ensure_ascii=False,
            ),
            language="json",
        )

    st.write(
        "**Cipher:**"
    )

    st.code(
        json.dumps(
            ssl_data.get(
                "cipher"
            ),
            indent=2,
            ensure_ascii=False,
        ),
        language="json",
    )

    st.write(
        "**Subject Alternative Names:**"
    )

    st.code(
        json.dumps(
            ssl_data.get(
                "san",
                []
            ),
            indent=2,
            ensure_ascii=False,
        ),
        language="json",
    )

    if ssl_data.get("error"):
        st.error(
            ssl_data["error"]
        )


def render_domain(report):
    rdap = report["rdap"]

    if rdap.get("error"):
        st.warning(
            f'RDAP: {rdap["error"]}'
        )

    c1, c2 = st.columns(2)

    with c1:
        st.write(
            "**Registrar:**",
            fmt(
                rdap.get(
                    "registrar"
                )
            )
        )

        st.write(
            "**Created:**",
            fmt(
                rdap.get(
                    "created"
                )
            )
        )

        st.write(
            "**Updated:**",
            fmt(
                rdap.get(
                    "updated"
                )
            )
        )

        st.write(
            "**Expires:**",
            fmt(
                rdap.get(
                    "expires"
                )
            )
        )

    with c2:
        st.write(
            "**RDAP Handle:**",
            fmt(
                rdap.get(
                    "handle"
                )
            )
        )

        st.write(
            "**Domain Status:**"
        )

        st.code(
            json.dumps(
                rdap.get(
                    "statuses",
                    []
                ),
                indent=2,
            ),
            language="json",
        )

        st.write(
            "**RDAP Nameservers:**"
        )

        st.code(
            json.dumps(
                rdap.get(
                    "nameservers",
                    []
                ),
                indent=2,
            ),
            language="json",
        )


def render_seo(report):
    seo = report["https"].get(
        "seo",
        {}
    )

    if not seo:
        st.warning(
            "HTML SEO data could not be extracted "
            "from the HTTPS response."
        )
        return

    c1, c2 = st.columns(2)

    with c1:
        st.write(
            "**Title:**",
            fmt(
                seo.get(
                    "title"
                )
            )
        )

        st.write(
            "**Title length:**",
            seo.get(
                "title_length",
                0
            )
        )

        st.write(
            "**Meta description:**",
            fmt(
                seo.get(
                    "meta_description"
                )
            )
        )

        st.write(
            "**Description length:**",
            seo.get(
                "meta_description_length",
                0
            )
        )

    with c2:
        st.write(
            "**Canonical:**",
            fmt(
                seo.get(
                    "canonical"
                )
            )
        )

        st.write(
            "**Meta robots:**",
            fmt(
                seo.get(
                    "meta_robots"
                )
            )
        )

        st.write(
            "**HTML language:**",
            fmt(
                seo.get(
                    "html_lang"
                )
            )
        )

        st.write(
            "**H1 count:**",
            seo.get(
                "h1_count",
                0
            )
        )

    st.divider()

    robots = report["robots_txt"]
    sitemap = report["sitemap_xml"]

    c3, c4 = st.columns(2)

    with c3:
        st.write(
            "**robots.txt**"
        )

        st.write(
            "Status:",
            fmt(
                robots.get(
                    "status"
                )
            )
        )

        st.write(
            "Final URL:",
            fmt(
                robots.get(
                    "final_url"
                )
            )
        )

        if robots.get("error"):
            st.error(
                robots["error"]
            )

    with c4:
        st.write(
            "**sitemap.xml**"
        )

        st.write(
            "Status:",
            fmt(
                sitemap.get(
                    "status"
                )
            )
        )

        st.write(
            "Final URL:",
            fmt(
                sitemap.get(
                    "final_url"
                )
            )
        )

        if sitemap.get("error"):
            st.error(
                sitemap["error"]
            )


def render_security(report):
    headers = report[
        "security_headers"
    ]

    st.write(
        "Security header presence on the final HTTPS response."
    )

    for name, data in headers.items():
        c1, c2 = st.columns(
            [0.25, 0.75]
        )

        with c1:
            if data["present"]:
                st.success(
                    f"{name}: Present"
                )
            else:
                st.warning(
                    f"{name}: Missing"
                )

        with c2:
            st.code(
                fmt(
                    data.get(
                        "value"
                    )
                ),
                language="text",
            )

    with st.expander(
        "All HTTPS response headers"
    ):
        st.code(
            json.dumps(
                report[
                    "https"
                ].get(
                    "headers",
                    {}
                ),
                indent=2,
                ensure_ascii=False,
            ),
            language="json",
        )


# =========================================================
# HEADER
# =========================================================

st.markdown(
    """
<div class="dc-hero">
    <div class="dc-eyebrow">DOMAIN INTELLIGENCE PLATFORM</div>
    <div class="dc-title">DOMAIN CHECKER</div>
    <div class="dc-subtitle">
        DNS · HTTP/HTTPS · Redirects · SSL/TLS · RDAP · SEO ·
        Robots · Sitemap · Security Headers · Infrastructure
    </div>
</div>
""",
    unsafe_allow_html=True,
)


# =========================================================
# INPUT
# =========================================================

input_col, button_col = st.columns(
    [5, 1]
)

with input_col:
    domain_input = st.text_input(
        "Target domain",
        placeholder="example.com",
        key="target_domain",
    )

with button_col:
    st.write("")
    st.write("")
    scan_clicked = st.button(
        "Analyze Domain",
        use_container_width=True,
    )


if scan_clicked:
    try:
        normalized = normalize_domain(
            domain_input
        )

        st.session_state[
            "domain_report"
        ] = run_scan(
            normalized
        )

    except ValueError as exc:
        st.error(
            str(exc)
        )

    except Exception as exc:
        st.error(
            f"Scan gagal: {exc}"
        )


# =========================================================
# RESULTS
# =========================================================

report = st.session_state.get(
    "domain_report"
)

if report:
    st.caption(
        f'Last analysis: {report["checked_at"]}'
    )

    tabs = st.tabs(
        [
            "Overview",
            "DNS",
            "HTTP & Redirects",
            "SSL / TLS",
            "Domain / RDAP",
            "SEO",
            "Security",
            "Export",
        ]
    )

    with tabs[0]:
        render_overview(
            report
        )

    with tabs[1]:
        render_dns(
            report
        )

    with tabs[2]:
        render_http(
            report
        )

    with tabs[3]:
        render_ssl(
            report
        )

    with tabs[4]:
        render_domain(
            report
        )

    with tabs[5]:
        render_seo(
            report
        )

    with tabs[6]:
        render_security(
            report
        )

    with tabs[7]:
        st.subheader(
            "Export Analysis"
        )

        json_data = json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        )

        safe_domain = re.sub(
            r"[^a-zA-Z0-9._-]",
            "_",
            report["domain"],
        )

        st.download_button(
            "Download JSON Report",
            data=json_data,
            file_name=(
                f"domain_report_{safe_domain}.json"
            ),
            mime="application/json",
            use_container_width=False,
        )

        st.caption(
            "JSON contains the DNS, HTTP, TLS, RDAP, SEO "
            "and security information displayed in this dashboard."
        )

else:
    st.markdown("")
    st.info(
        "Masukkan domain lalu klik **Analyze Domain** untuk memulai pemeriksaan."
    )

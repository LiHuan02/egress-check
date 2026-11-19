#!/usr/bin/env python3
"""egress-check — single-node egress quality scorecard for a proxy.

Give it one proxy (``socks5://`` or ``http(s)://``) and it runs an egress
checkup, then prints one scorecard answering "is this node usable, and for
what?":

  * alive — can the proxy be reached and does it forward traffic;
  * exit IP / geo / ASN — where the traffic actually comes out
    (country, city, ISP, AS number, via ip-api.com);
  * anonymity grade — transparent / anonymous / elite, judged by which
    proxy-identifying headers (``X-Forwarded-For``, ``Via``, ...) the exit
    path leaks to a header-echo endpoint, and whether the exit IP equals
    the direct IP;
  * latency — median of N requests through the proxy;
  * DNS — whether names are resolved on the proxy side (the proxy is only
    ever handed a hostname, never a locally resolved address).

Standard library only — no third-party dependencies. The SOCKS5 handshake
(RFC 1928, with username/password auth per RFC 1929) is implemented by
hand, because the standard library has no SOCKS client.

Exit status: 0 when the proxy is alive, 1 when it is dead, 2 on usage
errors — so it composes with scripts (``egress-check.py URL || echo down``).

Credentials in the proxy URL are never printed: reports show only
``scheme://host:port``.

Usage:
    egress-check.py socks5://user:pass@host:1080
    egress-check.py http://host:8080 --json
    egress-check.py socks5://host:1080 --samples 3 --timeout 8
    egress-check.py socks5://host:1080 --verdicts
    egress-check.py --self-test

This is stage 2 of the egress-check project (single-node mode + AI-service
verdicts). Stage 3 reads a Clash subscription YAML and scores every node
in it, stage 4 adds streaming-unlock checks and scheduled re-checks with
history.
"""

import argparse
import base64
import json
import socket
import ssl
import statistics
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

VERSION = "0.2.0"
USER_AGENT = "egress-check/" + VERSION

IP_API_URL = ("http://ip-api.com/json/"
              "?fields=status,message,country,countryCode,city,isp,org,as,query")
HEADERS_URL = "http://httpbin.org/headers"
DNS_PROBE_URL = "http://example.com/"
DNS_PROBE_HOST = "example.com"

# Headers that leak the client's real IP when present with that IP inside.
LEAK_HEADERS = ("x-forwarded-for", "forwarded", "x-real-ip")
# Headers that identify the request as proxied (superset of LEAK_HEADERS).
PROXY_HEADERS = LEAK_HEADERS + ("via", "x-proxy-id", "proxy-connection",
                                "x-forwarded-host", "x-forwarded-port")

ANONYMITY_POINTS = {"elite": 30, "anonymous": 20, "transparent": 0,
                    "unknown": 10}


class ProxyError(Exception):
    """Anything that goes wrong talking to (or through) the proxy."""


class FetchResult:
    """One HTTP response fetched through a proxy."""

    def __init__(self, status, headers, body, elapsed_ms):
        self.status = status
        self.headers = headers
        self.body = body
        self.elapsed_ms = elapsed_ms


class ProxySpec:
    """A parsed proxy URL. Credentials are kept off every report."""

    def __init__(self, scheme, host, port, username=None, password=None):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    @property
    def display(self):
        """Credential-free form, safe to print: scheme://host:port."""
        return f"{self.scheme}://{self.host}:{self.port}"


def parse_proxy_url(text):
    """Parse socks5:// or http(s)://[user:pass@]host[:port]."""
    try:
        u = urlparse(text)
    except ValueError as e:
        raise ProxyError(f"cannot parse proxy URL: {e}")
    scheme = (u.scheme or "").lower()
    if scheme == "socks5h":
        scheme = "socks5"
    if scheme not in ("socks5", "http", "https"):
        raise ProxyError(
            f"unsupported proxy scheme: {scheme!r} "
            "(want socks5:// or http(s)://)")
    if not u.hostname:
        raise ProxyError("proxy URL has no host")
    try:
        port = u.port
    except ValueError as e:
        raise ProxyError(f"bad port in proxy URL: {e}")
    if port is None:
        port = 1080 if scheme == "socks5" else 8080
    if not 1 <= port <= 65535:
        raise ProxyError(f"port out of range: {port}")
    return ProxySpec(scheme, u.hostname, port, u.username, u.password)


# --------------------------------------------------------------------------
# Socket plumbing
# --------------------------------------------------------------------------

def _recv_exact(sock, n):
    """Read exactly n bytes or raise ProxyError."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProxyError("proxy closed the connection mid-reply")
        buf += chunk
    return buf


def _recv_until(sock, marker, limit=65536):
    """Read until marker appears (headers) or raise ProxyError."""
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            raise ProxyError("proxy sent an oversized response")
    return buf


SOCKS5_REP = {0: "ok", 1: "general failure", 2: "connection not allowed",
              3: "network unreachable", 4: "host unreachable",
              5: "connection refused", 6: "TTL expired",
              7: "command not supported", 8: "address type not supported"}


def socks5_connect(spec, host, port, timeout, _connect=None):
    """Open a SOCKS5 tunnel to host:port. Returns the connected socket.

    The target is sent as a domain name (ATYP 0x03), so the proxy — not
    this machine — resolves it. ``_connect`` exists only so --self-test
    can inject a fake socket.
    """
    connect = _connect or socket.create_connection
    try:
        sock = connect((spec.host, spec.port), timeout=timeout)
    except Exception as e:
        raise ProxyError(
            f"cannot TCP-connect to proxy {spec.display}: "
            f"{type(e).__name__}: {e}")
    sock.settimeout(timeout)
    try:
        methods = [0x02] if spec.username else [0x00]
        sock.sendall(bytes([0x05, len(methods), *methods]))
        ver, method = _recv_exact(sock, 2)
        if ver != 0x05:
            raise ProxyError(
                f"{spec.display} is not a SOCKS5 proxy "
                f"(greeting reply version {ver})")
        if method == 0xFF:
            raise ProxyError(
                f"{spec.display} rejected all auth methods")
        if method == 0x02:
            user = spec.username.encode("utf-8")
            pw = (spec.password or "").encode("utf-8")
            if len(user) > 255 or len(pw) > 255:
                raise ProxyError("SOCKS5 username/password too long")
            sock.sendall(bytes([0x01, len(user)]) + user +
                        bytes([len(pw)]) + pw)
            aver, status = _recv_exact(sock, 2)
            if aver != 0x01 or status != 0x00:
                raise ProxyError(
                    f"SOCKS5 auth failed on {spec.display} "
                    f"(status {status})")
        elif method != 0x00:
            raise ProxyError(
                f"{spec.display} asked for unsupported auth "
                f"method {method}")
        host_b = host.encode("idna")
        if len(host_b) > 255:
            raise ProxyError("target hostname too long for SOCKS5")
        sock.sendall(bytes([0x05, 0x01, 0x00, 0x03, len(host_b)]) +
                    host_b + port.to_bytes(2, "big"))
        ver, rep, _rsv, atyp = _recv_exact(sock, 4)
        if ver != 0x05:
            raise ProxyError(
                f"{spec.display} replied with bad version {ver}")
        if rep != 0x00:
            raise ProxyError(
                f"SOCKS5 CONNECT to {host}:{port} failed: "
                f"{SOCKS5_REP.get(rep, f'error {rep}')}")
        if atyp == 0x01:
            _recv_exact(sock, 4)
        elif atyp == 0x03:
            ln = _recv_exact(sock, 1)[0]
            _recv_exact(sock, ln)
        elif atyp == 0x04:
            _recv_exact(sock, 16)
        else:
            raise ProxyError(
                f"{spec.display} returned unknown address type {atyp}")
        _recv_exact(sock, 2)  # bound port
        return sock
    except ProxyError:
        try:
            sock.close()
        except Exception:
            pass
        raise


def http_proxy_connect(spec, host, port, timeout, _connect=None):
    """CONNECT through an HTTP(S) proxy. Returns the tunnel socket."""
    connect = _connect or socket.create_connection
    try:
        sock = connect((spec.host, spec.port), timeout=timeout)
    except Exception as e:
        raise ProxyError(
            f"cannot TCP-connect to proxy {spec.display}: "
            f"{type(e).__name__}: {e}")
    sock.settimeout(timeout)
    auth = ""
    if spec.username:
        token = base64.b64encode(
            f"{spec.username}:{spec.password or ''}".encode()).decode()
        auth = f"Proxy-Authorization: Basic {token}\r\n"
    sock.sendall(
        f"CONNECT {host}:{port} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n{auth}\r\n".encode())
    raw = _recv_until(sock, b"\r\n\r\n")
    line = raw.decode("iso-8859-1", "replace").split("\r\n")[0]
    parts = line.split()
    if len(parts) < 2 or not parts[1].startswith("2"):
        raise ProxyError(
            f"HTTP proxy {spec.display} refused CONNECT to "
            f"{host}:{port}: {line}")
    return sock


def _read_chunked(sock, buf):
    """Decode a chunked body; buf holds bytes already read after headers."""
    body = b""
    while True:
        while b"\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise ProxyError("truncated chunked response")
            buf += chunk
        line, _, buf = buf.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            raise ProxyError(f"bad chunk size: {line!r}")
        if size == 0:
            return body
        while len(buf) < size + 2:
            chunk = sock.recv(65536)
            if not chunk:
                raise ProxyError("truncated chunked response")
            buf += chunk
        body += buf[:size]
        buf = buf[size + 2:]


def read_http_response(sock, timeout):
    """Read one HTTP/1.x response off an open socket."""
    sock.settimeout(timeout)
    raw = _recv_until(sock, b"\r\n\r\n")
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", "replace").split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        raise ProxyError(f"unparsable HTTP status line: {lines[0]!r}")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    body = rest
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = _read_chunked(sock, body)
    elif "content-length" in headers:
        try:
            total = int(headers["content-length"])
        except ValueError:
            raise ProxyError(
                f"bad Content-Length: {headers['content-length']!r}")
        while len(body) < total:
            chunk = sock.recv(min(65536, total - len(body)))
            if not chunk:
                break
            body += chunk
        body = body[:total]
    else:  # no length framing: read until close (we sent Connection: close)
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
    return status, headers, body


def _http_get_on_socket(sock, host, path, timeout):
    """Send a GET on an already-open tunnel; return (status, headers, body)."""
    sock.sendall(
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n".encode())
    return read_http_response(sock, timeout)


def _proxy_auth_header(spec):
    if not spec.username:
        return ""
    token = base64.b64encode(
        f"{spec.username}:{spec.password or ''}".encode()).decode()
    return f"Proxy-Authorization: Basic {token}\r\n"


def _tls_wrap(sock, host, timeout):
    """Wrap an open tunnel socket in TLS (for https:// targets)."""
    ctx = ssl.create_default_context()
    try:
        wrapped = ctx.wrap_socket(sock, server_hostname=host)
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        raise ProxyError(
            f"TLS handshake to {host} failed: {type(e).__name__}: {e}")
    wrapped.settimeout(timeout)
    return wrapped


def http_fetch_via_proxy(spec, url, timeout, _connect=None):
    """GET url through the proxy. Returns a FetchResult.

    Plain-HTTP targets go over a CONNECT tunnel for HTTP proxies; if the
    proxy refuses CONNECT on port 80, fall back to an absolute-URI GET
    (the classic HTTP-proxy request form). HTTPS targets always go over
    a tunnel (SOCKS5 CONNECT or HTTP CONNECT) wrapped in TLS — the
    proxy sees only the destination host, never the plaintext.
    """
    u = urlparse(url)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    connect = _connect or socket.create_connection
    start = time.monotonic()
    sock = None
    try:
        if spec.scheme == "socks5":
            sock = socks5_connect(spec, host, port, timeout,
                                  _connect=connect)
            if u.scheme == "https":
                sock = _tls_wrap(sock, host, timeout)
            status, headers, body = _http_get_on_socket(
                sock, host, path, timeout)
        else:
            try:
                sock = http_proxy_connect(spec, host, port, timeout,
                                          _connect=connect)
                if u.scheme == "https":
                    sock = _tls_wrap(sock, host, timeout)
                status, headers, body = _http_get_on_socket(
                    sock, host, path, timeout)
            except ProxyError:
                if u.scheme != "http":
                    raise
                if sock is not None:
                    sock.close()
                try:
                    sock = connect((spec.host, spec.port), timeout=timeout)
                except Exception as e:
                    raise ProxyError(
                        f"cannot TCP-connect to proxy {spec.display}: "
                        f"{type(e).__name__}: {e}")
                sock.settimeout(timeout)
                sock.sendall(
                    f"GET {url} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {USER_AGENT}\r\n"
                    f"Accept: */*\r\n"
                    f"{_proxy_auth_header(spec)}"
                    f"Connection: close\r\n\r\n".encode())
                status, headers, body = read_http_response(sock, timeout)
        ms = (time.monotonic() - start) * 1000
        return FetchResult(status, headers, body, ms)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def http_get_direct(url, timeout):
    """GET url without any proxy (env proxies ignored). Returns parsed
    JSON dict, or None on any failure. Used only for the direct-IP
    baseline; a failure degrades the anonymity grade, it never aborts
    the check."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

def grade_anonymity(seen_headers, exit_ip, direct_ip):
    """Grade transparent / anonymous / elite from echoed request headers.

    seen_headers: the request headers a header-echo endpoint saw (any
    casing). transparent = the client's real (direct) IP is leaked, or
    the exit IP equals the direct IP; anonymous = the proxy identifies
    itself (Via, X-Forwarded-For, ...) but leaks no client IP; elite =
    no proxy-identifying header at all.
    """
    headers = {k.lower(): v for k, v in (seen_headers or {}).items()}
    if direct_ip and exit_ip and direct_ip == exit_ip:
        return ("transparent",
                ["exit IP equals direct IP — the proxy is not hiding "
                 "the client"])
    if direct_ip:
        for name in LEAK_HEADERS:
            if direct_ip in headers.get(name, ""):
                return ("transparent",
                        [f"{name} leaks the client IP"])
    present = [n for n in PROXY_HEADERS if n in headers]
    if present:
        return ("anonymous",
                ["proxy-identifying headers present: "
                 + ", ".join(present) + "; client IP not leaked"])
    return ("elite", ["no proxy-identifying headers seen"])


def dns_probe(spec, fetch, timeout):
    """Check whether names are resolved on the proxy side.

    The probe fetch hands the proxy only a hostname (SOCKS5 CONNECT with
    a domain name, or an absolute-URI GET for HTTP proxies), so the
    lookup happens on the proxy side by construction. As extra evidence,
    the local resolver is tried first: if it fails while the proxy fetch
    succeeds, remote resolution is proven, not just assumed.
    """
    try:
        socket.getaddrinfo(DNS_PROBE_HOST, 80, proto=socket.IPPROTO_TCP)
        local_ok = True
    except Exception:
        local_ok = False
    try:
        res = fetch(spec, DNS_PROBE_URL, timeout)
        proxy_ok = res.status < 400
    except Exception:
        proxy_ok = False
    if proxy_ok and not local_ok:
        return {"mode": "remote", "local_dns_works": False,
                "proxy_fetch_ok": True,
                "evidence": "local resolver failed for the probe host, "
                            "yet the proxy fetched it — the proxy "
                            "resolved the name"}
    if proxy_ok:
        return {"mode": "remote", "local_dns_works": True,
                "proxy_fetch_ok": True,
                "evidence": "proxy was given only the hostname, so the "
                            "lookup happened on the proxy side"}
    return {"mode": "unknown", "local_dns_works": local_ok,
            "proxy_fetch_ok": False,
            "evidence": "probe fetch through the proxy failed — DNS "
                        "path could not be verified"}


# --------------------------------------------------------------------------
# Service verdicts (stage 2)
# --------------------------------------------------------------------------
#
# One small GET per service, through the same proxy. No credentials and
# no accounts are involved: the verdicts only ask whether the exit can
# reach the service at all, and what stands in the way when it cannot.
# Redirects are deliberately NOT followed — a redirect target is itself
# evidence (Google sending the exit to google.com.hk is the "sent to
# China" signal).

# (key, display name, probe URL)
VERDICT_SERVICES = (
    ("gemini", "Gemini API",
     "https://generativelanguage.googleapis.com/v1beta/models"),
    ("claude", "Claude", "https://claude.ai/"),
    ("chatgpt", "ChatGPT", "https://chatgpt.com/"),
    ("youtube", "YouTube", "https://www.youtube.com/"),
    ("github", "GitHub", "https://api.github.com/"),
    ("google", "Google", "https://www.google.com/"),
)

# Verdicts: ok | region-blocked | captcha | sent-to-china | blocked | error
CLOUDFLARE_MARKERS = ("just a moment", "attention required",
                      "cf-challenge", "challenges.cloudflare.com")
REGION_MARKERS = ("not supported in your region",
                  "location is not supported",
                  "not available in your region",
                  "not available in your country",
                  "is not available in your country",
                  "unsupported country",
                  "not supported for the api use")


def _body_text(res):
    try:
        return res.body.decode("utf-8", "replace")
    except Exception:
        return ""


def _is_cloudflare_challenge(res):
    text = _body_text(res).lower()
    return any(m in text for m in CLOUDFLARE_MARKERS)


def _mentions_region_block(text):
    low = text.lower()
    return any(m in low for m in REGION_MARKERS)


def classify_verdict(service, res, exit_country_code=None):
    """Classify one probe response. Returns (verdict, evidence).

    res is a FetchResult. A missing/failed fetch is handled by the
    caller (run_verdicts) as "blocked"; this function only sees real
    HTTP responses.
    """
    status = res.status
    text = _body_text(res)
    if _is_cloudflare_challenge(res):
        return ("captcha",
                f"HTTP {status}, Cloudflare verification page served")
    if service == "google":
        loc = (res.headers.get("location") or "").lower()
        if "google.com.hk" in loc or "google.cn" in loc:
            return ("sent-to-china",
                    f"google.com redirects to {loc} while the exit is "
                    f"in {exit_country_code or 'unknown'} — Google "
                    f"georoutes this exit to China/HK")
        if status in (200, 301, 302, 303, 307, 308):
            return ("ok", f"HTTP {status}"
                    + (f", redirects to {loc}" if loc else ""))
        return ("blocked", f"HTTP {status}")
    if service == "gemini":
        # No API key is sent, so 400/401/403 auth errors are the
        # *expected* answer from a reachable Google — the egress works,
        # the key is just missing. Only an explicit region refusal
        # counts as region-blocked.
        if status == 200:
            return ("ok", "HTTP 200")
        if status in (400, 401, 403):
            if _mentions_region_block(text):
                return ("region-blocked",
                        f"HTTP {status}, Google refuses this region")
            return ("ok",
                    f"HTTP {status} (auth error expected without an "
                    f"API key — the API itself is reachable)")
        if status == 429:
            return ("blocked", "HTTP 429 rate-limited")
        if status >= 500:
            return ("error", f"HTTP {status} from Google")
        return ("blocked", f"HTTP {status}")
    # claude / chatgpt / youtube / github
    if status in (200, 301, 302, 303, 307, 308):
        return ("ok", f"HTTP {status}")
    if status == 403:
        if _mentions_region_block(text):
            return ("region-blocked",
                    f"HTTP {status}, service refuses this region")
        if "abuse" in text.lower():
            return ("blocked",
                    "HTTP 403 abuse / rate-limit detection")
        return ("blocked", f"HTTP {status} forbidden")
    if status == 429:
        return ("blocked", "HTTP 429 rate-limited")
    if status >= 500:
        return ("error", f"HTTP {status} from the service")
    return ("blocked", f"HTTP {status}")


def run_verdicts(spec, fetch, timeout, exit_country_code=None):
    """Probe every VERDICT_SERVICES URL through the proxy.

    Returns {key: {"service", "url", "verdict", "evidence", "status"}}.
    A fetch that raises (timeout, DNS, TLS, proxy refusal) is
    "blocked" — the exit could not reach the service at all.
    """
    out = {}
    for key, label, url in VERDICT_SERVICES:
        try:
            res = fetch(spec, url, timeout)
        except Exception as e:
            out[key] = {"service": label, "url": url,
                        "verdict": "blocked",
                        "evidence": f"{type(e).__name__}: {e}",
                        "status": None}
            continue
        verdict, evidence = classify_verdict(key, res, exit_country_code)
        out[key] = {"service": label, "url": url, "verdict": verdict,
                    "evidence": evidence, "status": res.status}
    return out


def latency_points(median_ms):
    """Latency sub-score (20 max) from the median sample."""
    if median_ms is None:
        return 0
    if median_ms <= 150:
        return 20
    if median_ms <= 300:
        return 15
    if median_ms <= 600:
        return 10
    if median_ms <= 1200:
        return 5
    return 0


def score_result(alive, median_ms, anonymity, dns_mode):
    """Overall score (100 max) and letter grade.

    alive 30 + latency 20 + anonymity 30 + DNS 20. A dead proxy scores
    0 outright — the other checks never ran.
    """
    if not alive:
        return 0, "F"
    pts = 30 + latency_points(median_ms)
    pts += ANONYMITY_POINTS.get(anonymity, 10)
    pts += 20 if dns_mode == "remote" else 0
    if pts >= 80:
        grade = "A"
    elif pts >= 60:
        grade = "B"
    elif pts >= 40:
        grade = "C"
    else:
        grade = "D"
    return pts, grade


def run_check(spec, timeout=10.0, samples=5, fetch=None, direct_fetch=None,
              verdicts=False):
    """Run the full checkup. Returns a JSON-able result dict.

    verdicts=True additionally probes the AI services (stage 2) once
    the proxy is known alive; the verdicts are reported as-is and do
    not change the 0-100 score.
    """
    fetch = fetch or http_fetch_via_proxy
    direct_fetch = direct_fetch or http_get_direct
    result = {"proxy": spec.display, "scheme": spec.scheme,
              "alive": False, "exit_ip": None, "country": None,
              "country_code": None, "city": None, "isp": None,
              "org": None, "asn": None, "latency_ms": None,
              "anonymity": "unknown", "anonymity_evidence": [],
              "dns": {"mode": "unknown", "evidence": "not run"},
              "verdicts": None,
              "direct_ip": None, "score": 0, "grade": "F",
              "error": None}

    direct = direct_fetch(IP_API_URL, timeout)
    if direct and direct.get("status") == "success":
        result["direct_ip"] = direct.get("query")

    try:
        first = fetch(spec, IP_API_URL, timeout)
        geo = {}
        if first.status == 200:
            try:
                geo = json.loads(first.body.decode("utf-8", "replace"))
            except ValueError:
                geo = {}
        if first.status != 200 or geo.get("status") != "success":
            raise ProxyError(
                f"IP info endpoint returned HTTP {first.status}")
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result

    samples_ms = [first.elapsed_ms]
    for _ in range(max(0, samples - 1)):
        try:
            samples_ms.append(fetch(spec, IP_API_URL, timeout).elapsed_ms)
        except Exception:
            pass
    median_ms = statistics.median(samples_ms)
    result["latency_ms"] = {
        "median": round(median_ms),
        "min": round(min(samples_ms)),
        "max": round(max(samples_ms)),
        "samples": len(samples_ms),
    }

    result.update(alive=True, exit_ip=geo.get("query"),
                  country=geo.get("country"), country_code=geo.get("countryCode"),
                  city=geo.get("city"), isp=geo.get("isp"),
                  org=geo.get("org"), asn=geo.get("as"))

    try:
        hb = fetch(spec, HEADERS_URL, timeout)
        seen = {}
        if hb.status == 200:
            try:
                seen = json.loads(hb.body.decode("utf-8", "replace")).get(
                    "headers", {})
            except ValueError:
                seen = {}
        anon, evidence = grade_anonymity(seen, result["exit_ip"],
                                         result["direct_ip"])
    except Exception:
        anon, evidence = ("unknown",
                          ["header-echo endpoint unreachable through "
                           "the proxy"])
    result["anonymity"] = anon
    result["anonymity_evidence"] = evidence

    result["dns"] = dns_probe(spec, fetch, timeout)

    if verdicts:
        result["verdicts"] = run_verdicts(
            spec, fetch, timeout, result.get("country_code"))

    result["score"], result["grade"] = score_result(
        True, median_ms, anon, result["dns"]["mode"])
    return result


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def render_table(result):
    """Human-readable scorecard. Never prints proxy credentials."""
    def row(label, value):
        return f"{label:<12} {value}"

    lines = [f"egress-check  {result['proxy']}"]
    if not result["alive"]:
        lines.append(row("alive", "no"))
        lines.append(row("error", result["error"] or "unknown"))
        lines.append(row("score", "0/100 (F)"))
        return "\n".join(lines)
    geo = ", ".join(x for x in (result["city"], result["country"])
                    if x)
    if result["country_code"]:
        geo += f" ({result['country_code']})"
    lat = result["latency_ms"]
    lines.append(row("alive", "yes"))
    lines.append(row("exit IP", result["exit_ip"] or "n/a"))
    lines.append(row("geo", geo or "n/a"))
    lines.append(row("ASN", result["asn"] or "n/a"))
    lines.append(row("ISP", result["isp"] or result["org"] or "n/a"))
    lines.append(row("latency",
                     f"median {lat['median']} ms "
                     f"(min {lat['min']}, max {lat['max']}; "
                     f"{lat['samples']} samples)"))
    lines.append(row("anonymity",
                     result["anonymity"] + " — " +
                     "; ".join(result["anonymity_evidence"])))
    lines.append(row("DNS",
                     result["dns"]["mode"] + " — " +
                     result["dns"]["evidence"]))
    if result.get("verdicts"):
        lines.append("verdicts")
        for key, _label, _url in VERDICT_SERVICES:
            v = result["verdicts"][key]
            lines.append(f"  {v['service']:<11} {v['verdict']} — "
                         f"{v['evidence']}")
    lines.append(row("score",
                     f"{result['score']}/100 ({result['grade']})"))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Self-test (fully offline)
# --------------------------------------------------------------------------

class _FakeSocket:
    """A socket that replays canned bytes and records what was sent."""

    def __init__(self, recv_bytes):
        self._recv = recv_bytes
        self.sent = b""
        self.timeout = None

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        chunk, self._recv = self._recv[:n], self._recv[n:]
        return chunk

    def settimeout(self, timeout):
        self.timeout = timeout

    def close(self):
        pass


def _stub_fetch_factory():
    """A fake fetch() serving canned responses for --self-test."""
    def fetch(spec, url, timeout):
        if "ip-api.com" in url:
            body = json.dumps({
                "status": "success", "country": "United States",
                "countryCode": "US", "city": "Los Angeles",
                "isp": "Example ISP", "org": "Example Org",
                "as": "AS12345 Example", "query": "203.0.113.7"}).encode()
            return FetchResult(200, {}, body, 120.0)
        if "httpbin.org" in url:
            body = json.dumps({"headers": {
                "Host": "httpbin.org", "User-Agent": "egress-check"}}).encode()
            return FetchResult(200, {}, body, 90.0)
        if "example.com" in url:
            return FetchResult(200, {}, b"<!doctype html>", 100.0)
        if "generativelanguage.googleapis.com" in url:
            body = json.dumps({"error": {
                "code": 400,
                "message": "API key not valid. Please pass a valid "
                           "API key."}}).encode()
            return FetchResult(400, {}, body, 80.0)
        if "claude.ai" in url:
            return FetchResult(200, {}, b"<html>Claude</html>", 110.0)
        if "chatgpt.com" in url:
            return FetchResult(200, {}, b"<html>ChatGPT</html>", 100.0)
        if "youtube.com" in url:
            return FetchResult(200, {}, b"<html>YouTube</html>", 130.0)
        if "api.github.com" in url:
            body = json.dumps(
                {"current_user_url": "https://api.github.com/user"}).encode()
            return FetchResult(200, {}, body, 90.0)
        if "google.com" in url:
            return FetchResult(200, {}, b"<html>Google</html>", 95.0)
        raise ProxyError(f"stub: unexpected URL {url}")
    return fetch


def _stub_direct(url, timeout):
    return {"status": "success", "query": "198.51.100.9"}


def self_test():
    """Offline checks. Returns True when every test passes."""
    tests = []

    def check(name):
        def deco(fn):
            tests.append((name, fn))
            return fn
        return deco

    @check("parse: socks5 with auth and default ports")
    def _():
        s = parse_proxy_url("socks5://user:pass@host.example:1080")
        assert (s.scheme, s.host, s.port, s.username, s.password) == \
            ("socks5", "host.example", 1080, "user", "pass")
        assert parse_proxy_url("socks5://h").port == 1080
        assert parse_proxy_url("http://h").port == 8080
        assert parse_proxy_url("https://h:8443").port == 8443
        assert parse_proxy_url("socks5://h").display == "socks5://h:1080"

    @check("parse: bad scheme / host / port rejected")
    def _():
        for bad in ("ftp://h:21", "http://", "socks5://h:0",
                    "socks5://h:99999", "socks5://h:abc", "not a url"):
            try:
                parse_proxy_url(bad)
            except ProxyError:
                continue
            raise AssertionError(f"{bad!r} should have been rejected")

    @check("socks5: no-auth handshake bytes")
    def _():
        spec = parse_proxy_url("socks5://127.0.0.1:1080")
        fake = _FakeSocket(bytes([5, 0]) +          # greeting reply
                           bytes([5, 0, 0, 1, 203, 0, 113, 1, 0, 80]))
        sock = socks5_connect(spec, "example.com", 80, 5,
                              _connect=lambda a, timeout: fake)
        assert sock is fake
        assert fake.sent == (bytes([5, 1, 0]) +     # greeting: no auth
                             bytes([5, 1, 0, 3, 11]) +
                             b"example.com" + (80).to_bytes(2, "big"))

    @check("socks5: user/pass auth handshake bytes")
    def _():
        spec = parse_proxy_url("socks5://u:p@127.0.0.1:1080")
        fake = _FakeSocket(bytes([5, 2]) + bytes([1, 0]) +
                           bytes([5, 0, 0, 1, 1, 2, 3, 4, 1, 187]))
        socks5_connect(spec, "example.com", 443, 5,
                       _connect=lambda a, timeout: fake)
        assert fake.sent == (bytes([5, 1, 2]) +     # greeting: user/pass
                             bytes([1, 1]) + b"u" + bytes([1]) + b"p" +
                             bytes([5, 1, 0, 3, 11]) + b"example.com" +
                             (443).to_bytes(2, "big"))

    @check("socks5: refused CONNECT raises")
    def _():
        spec = parse_proxy_url("socks5://127.0.0.1:1080")
        fake = _FakeSocket(bytes([5, 0]) + bytes([5, 5, 0, 1, 0, 0, 0, 0, 0, 0]))
        try:
            socks5_connect(spec, "example.com", 80, 5,
                           _connect=lambda a, timeout: fake)
        except ProxyError as e:
            assert "refused" in str(e)
            return
        raise AssertionError("expected ProxyError")

    @check("http: content-length and chunked bodies parse")
    def _():
        body = b'{"a":1}'
        fake = _FakeSocket(
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n" + body)
        status, headers, got = read_http_response(fake, 5)
        assert (status, got) == (200, body)
        fake = _FakeSocket(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")
        status, headers, got = read_http_response(fake, 5)
        assert got == b"Wikipedia"

    @check("http proxy: CONNECT tunnel + absolute-URI fallback")
    def _():
        spec = parse_proxy_url("http://127.0.0.1:8080")
        fake = _FakeSocket(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        sock = http_proxy_connect(spec, "example.com", 80, 5,
                                  _connect=lambda a, timeout: fake)
        assert sock is fake
        assert fake.sent.startswith(b"CONNECT example.com:80 HTTP/1.1")
        # CONNECT refused -> fall back to absolute-URI GET for plain HTTP
        fake1 = _FakeSocket(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        fake2 = _FakeSocket(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        fakes = [fake1, fake2]
        res = http_fetch_via_proxy(
            spec, "http://example.com/", 5,
            _connect=lambda a, timeout: fakes.pop(0))
        assert res.status == 200 and res.body == b"{}"
        assert fake2.sent.startswith(b"GET http://example.com/")

    @check("anonymity: transparent / anonymous / elite / unknown")
    def _():
        grade, _ = grade_anonymity(
            {"X-Forwarded-For": "198.51.100.9"}, "203.0.113.7",
            "198.51.100.9")
        assert grade == "transparent"
        grade, _ = grade_anonymity(
            {"Via": "1.1 proxy"}, "203.0.113.7", "198.51.100.9")
        assert grade == "anonymous"
        grade, _ = grade_anonymity(
            {"Host": "httpbin.org"}, "203.0.113.7", "198.51.100.9")
        assert grade == "elite"
        grade, _ = grade_anonymity(
            {"Host": "httpbin.org"}, "203.0.113.7", "203.0.113.7")
        assert grade == "transparent"  # exit == direct

    @check("scoring: boundaries and dead proxy")
    def _():
        assert score_result(True, 100, "elite", "remote") == (100, "A")
        assert score_result(True, 250, "anonymous", "remote") == (85, "A")
        assert score_result(True, 900, "anonymous", "unknown") == (55, "C")
        assert score_result(True, 5000, "transparent", "unknown") == (30, "D")
        assert score_result(False, None, "unknown", "unknown") == (0, "F")
        assert latency_points(150) == 20
        assert latency_points(1200) == 5
        assert latency_points(1201) == 0

    @check("run_check: stubbed happy path scores 100 (A)")
    def _():
        spec = parse_proxy_url("socks5://127.0.0.1:1080")
        res = run_check(spec, timeout=5, samples=3,
                        fetch=_stub_fetch_factory(),
                        direct_fetch=_stub_direct)
        assert res["alive"] is True
        assert res["exit_ip"] == "203.0.113.7"
        assert res["country_code"] == "US"
        assert res["anonymity"] == "elite"
        assert res["dns"]["mode"] == "remote"
        assert (res["score"], res["grade"]) == (100, "A")
        table = render_table(res)
        assert "203.0.113.7" in table and "100/100 (A)" in table
        data = json.loads(json.dumps(res))  # JSON-able
        assert data["latency_ms"]["samples"] == 3

    @check("run_check: dead proxy scores 0 and renders")
    def _():
        def dead(spec, url, timeout):
            raise ProxyError("stub: connection refused")
        spec = parse_proxy_url("socks5://127.0.0.1:1080")
        res = run_check(spec, timeout=5, samples=3, fetch=dead,
                        direct_fetch=_stub_direct)
        assert res["alive"] is False and res["score"] == 0
        assert "no" in render_table(res)

    @check("verdicts: classify gemini / google / captcha / region-blocked")
    def _():
        v, _ = classify_verdict(
            "gemini", FetchResult(400, {}, json.dumps(
                {"error": {"message": "API key not valid"}}).encode(), 10.0))
        assert v == "ok"  # auth error, no key: API itself reachable
        v, _ = classify_verdict(
            "gemini", FetchResult(400, {}, json.dumps(
                {"error": {"message": "User location is not supported "
                                      "for the API use"}}).encode(), 10.0))
        assert v == "region-blocked"
        v, ev = classify_verdict(
            "google",
            FetchResult(302, {"location": "https://www.google.com.hk/"},
                        b"", 10.0), "US")
        assert v == "sent-to-china" and "US" in ev
        v, _ = classify_verdict(
            "google", FetchResult(200, {}, b"ok", 10.0), "US")
        assert v == "ok"
        v, _ = classify_verdict(
            "chatgpt",
            FetchResult(403, {}, b"<title>Just a moment...</title>", 10.0))
        assert v == "captcha"
        v, _ = classify_verdict(
            "youtube", FetchResult(403, {}, b"Forbidden", 10.0))
        assert v == "blocked"
        v, _ = classify_verdict(
            "claude", FetchResult(200, {}, b"ok", 10.0))
        assert v == "ok"

    @check("verdicts: run_verdicts via stub covers all six services")
    def _():
        spec = parse_proxy_url("socks5://127.0.0.1:1080")
        out = run_verdicts(spec, _stub_fetch_factory(), 5, "US")
        assert set(out) == {"gemini", "claude", "chatgpt",
                            "youtube", "github", "google"}
        assert out["gemini"]["verdict"] == "ok"
        assert out["claude"]["verdict"] == "ok"
        assert out["github"]["verdict"] == "ok"
        assert out["google"]["verdict"] == "ok"
        assert all(v["status"] is not None for v in out.values())

    @check("verdicts: fetch failure is blocked, not a crash")
    def _():
        def boom(spec, url, timeout):
            raise ProxyError("stub: timeout")
        out = run_verdicts(parse_proxy_url("socks5://127.0.0.1:1080"),
                           boom, 5, "US")
        assert all(v["verdict"] == "blocked" for v in out.values())

    @check("run_check: verdicts=True adds verdicts and renders them")
    def _():
        spec = parse_proxy_url("socks5://127.0.0.1:1080")
        res = run_check(spec, timeout=5, samples=1,
                        fetch=_stub_fetch_factory(),
                        direct_fetch=_stub_direct, verdicts=True)
        assert res["verdicts"] is not None
        assert res["verdicts"]["gemini"]["verdict"] == "ok"
        table = render_table(res)
        assert "verdicts" in table and "Gemini API" in table
        assert json.loads(json.dumps(res))["verdicts"]["google"][
            "verdict"] == "ok"

    @check("https: TLS wrap failure surfaces as ProxyError")
    def _():
        # A fake socket is not a real socket, so the TLS handshake
        # cannot run; the failure must still come back as ProxyError,
        # never a raw ssl/socket error.
        spec = parse_proxy_url("socks5://127.0.0.1:1080")
        fake = _FakeSocket(bytes([5, 0]) +
                           bytes([5, 0, 0, 1, 203, 0, 113, 1, 0, 80]))
        try:
            http_fetch_via_proxy(spec, "https://example.com/", 5,
                                 _connect=lambda a, timeout: fake)
        except ProxyError:
            return
        raise AssertionError("expected ProxyError from failed TLS wrap")

    @check("run_check: credentials never appear in output")
    def _():
        spec = parse_proxy_url("socks5://secretuser:secretpass@127.0.0.1:1080")
        res = run_check(spec, timeout=5, samples=1,
                        fetch=_stub_fetch_factory(),
                        direct_fetch=_stub_direct)
        blob = render_table(res) + json.dumps(res)
        assert "secretuser" not in blob and "secretpass" not in blob

    passed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as e:
            print(f"FAIL {name}: {type(e).__name__}: {e}")
        else:
            print(f"PASS {name}")
            passed += 1
    print(f"{passed}/{len(tests)} self-tests passed")
    return passed == len(tests)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="egress-check",
        description="Single-node egress quality scorecard for a proxy.")
    parser.add_argument("proxy", nargs="?",
                        help="proxy URL, e.g. socks5://user:pass@host:1080 "
                             "or http://host:8080")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="per-request timeout in seconds (default 10)")
    parser.add_argument("--samples", type=int, default=5,
                        help="latency samples to take (default 5)")
    parser.add_argument("--verdicts", action="store_true",
                        help="also probe AI services (Gemini, Claude, "
                             "ChatGPT, YouTube, GitHub, Google) and report "
                             "reachability verdicts incl. sent-to-China "
                             "detection")
    parser.add_argument("--json", action="store_true",
                        help="print the result as JSON instead of a table")
    parser.add_argument("--self-test", action="store_true",
                        help="run the offline self-test suite and exit")
    parser.add_argument("--version", action="version",
                        version=f"egress-check {VERSION}")
    args = parser.parse_args(argv)

    if args.self_test:
        return 0 if self_test() else 1
    if not args.proxy:
        parser.error("a proxy URL is required (or --self-test)")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.samples < 1:
        parser.error("--samples must be at least 1")

    try:
        spec = parse_proxy_url(args.proxy)
    except ProxyError as e:
        print(f"egress-check: {e}", file=sys.stderr)
        return 2

    result = run_check(spec, timeout=args.timeout, samples=args.samples,
                       verdicts=args.verdicts)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(render_table(result))
    return 0 if result["alive"] else 1


if __name__ == "__main__":
    sys.exit(main())

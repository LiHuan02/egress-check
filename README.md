# egress-check

A single-file, zero-dependency CLI that scores one proxy's **egress
quality**: is this node alive, where does traffic actually come out, does
it leak your real IP, how slow is it, does DNS leak — and, with
`--verdicts`, can the exit actually reach the AI services you care
about (Gemini, Claude, ChatGPT, YouTube, GitHub, Google), or is it
geo-routed to China?

```text
$ python3 egress-check.py socks5://user:pass@host:1080 --verdicts
egress-check  socks5://host:1080
alive        yes
exit IP      203.0.113.7
geo          Los Angeles, United States (US)
ASN          AS12345 Example
ISP          Example ISP
latency      median 120 ms (min 98, max 210; 5 samples)
anonymity    elite — no proxy-identifying headers seen
DNS          remote — proxy was given only the hostname, so the lookup happened on the proxy side
verdicts
  Gemini API  ok — HTTP 400 (auth error expected without an API key — the API itself is reachable)
  Claude      ok — HTTP 200
  ChatGPT     ok — HTTP 200
  YouTube     ok — HTTP 200
  GitHub      ok — HTTP 200
  Google      ok — HTTP 200
score        100/100 (A)
```

Exit status: `0` when the proxy is alive, `1` when it is dead, `2` on
usage errors — so it composes with scripts
(`egress-check.py socks5://host:1080 || echo "node down"`).

## Why this exists

"Is the node up?" is the wrong question when you are picking a proxy to
actually use. The questions that matter are: does traffic come out where
the node claims (or is it geo-routed somewhere unexpected), does the
egress IP get flagged by the services you use, does the proxy leak your
real IP through `X-Forwarded-For`, and is DNS resolved on the proxy side
or on your machine? This tool answers all of those in one run, in one
file, with no server and no dependencies.

It is the egress companion to
[clash-yaml-check](https://github.com/LiHuan02/clash-yaml-check) (static
semantic checks for a subscription file) and
[clash-sub-health](https://github.com/LiHuan02/clash-sub-health) (liveness
probes). The three tools deliberately do not overlap: one reads the file,
one checks the nodes are up, this one checks what the exit looks like.

## Usage

```
python3 egress-check.py socks5://user:pass@host:1080
python3 egress-check.py http://host:8080 --json
python3 egress-check.py socks5://host:1080 --samples 3 --timeout 8
python3 egress-check.py socks5://host:1080 --verdicts
python3 egress-check.py --self-test
```

* The proxy URL is `socks5://` or `http(s)://`, with optional
  `user:pass@`. Default ports: 1080 (socks5), 8080 (http). Credentials
  are never printed: reports show only `scheme://host:port`.
* `--samples` sets how many requests the latency median is taken over
  (default 5). `--timeout` sets the per-request timeout in seconds
  (default 10).
* `--verdicts` additionally probes six services through the proxy and
  reports one verdict per service (see below). Off by default, so a
  plain run stays fast.
* `--json` prints the full result as machine-readable JSON instead of
  the table.

## How each check works

* **Alive / exit IP / geo / ASN** — a request to ip-api.com through the
  proxy. Country, city, ISP and AS number come from the same response.
* **Latency** — median of N requests to the same endpoint through the
  proxy (min/max also reported).
* **Anonymity** — a request to a header-echo endpoint (httpbin.org)
  through the proxy, then the echoed request headers are graded:
  *transparent* if the client's real (direct) IP shows up in
  `X-Forwarded-For`/`Forwarded`/`X-Real-IP`, or the exit IP equals the
  direct IP; *anonymous* if proxy-identifying headers (`Via`,
  `X-Forwarded-For`, ...) are present but leak no client IP; *elite* if
  no proxy-identifying header is seen at all. The direct IP is fetched
  once without the proxy for comparison; if that fetch fails, the grade
  falls back to header-only evidence.
* **DNS** — the probe fetch hands the proxy only a hostname (SOCKS5
  CONNECT with a domain name, or an absolute-URI GET for HTTP proxies),
  so the lookup happens on the proxy side by construction. As extra
  evidence the local resolver is tried first: if it fails while the
  proxy fetch succeeds, remote resolution is proven, not just assumed.
* **Service verdicts** (`--verdicts`) — one small GET per service
  through the same proxy, over a TLS-wrapped tunnel (the proxy sees
  only the destination host, never the plaintext). No accounts, keys
  or logins are involved; each probe just asks whether the exit can
  reach the service. Redirects are deliberately *not* followed — the
  redirect target is itself evidence. Verdicts:
  * `ok` — the service answered (for the Gemini API, a 400/401/403
    auth error *is* the expected answer without an API key: the API
    is reachable, the key is just missing).
  * `region-blocked` — the service answered but refuses this region
    ("not supported in your region", "location is not supported").
  * `captcha` — a Cloudflare verification page ("Just a moment",
    "Attention Required") was served instead of the service.
  * `sent-to-china` — Google only: `google.com` redirects the exit
    to `google.com.hk` / `google.cn` while the exit IP is elsewhere,
    i.e. Google georoutes this exit to China/HK.
  * `blocked` — no answer at all (timeout, DNS/TLS failure, proxy
    refusal) or a plain 403/429.
  * `error` — the service answered with a 5xx.
  Verdicts are reported as-is and do **not** change the 0–100 score.

## Scoring

| Check | Points | Rule |
| --- | --- | --- |
| Alive | 30 | 0 if dead — a dead proxy scores 0 outright |
| Latency (median) | 20 | ≤150 ms: 20; ≤300: 15; ≤600: 10; ≤1200: 5; else 0 |
| Anonymity | 30 | elite 30; anonymous 20; transparent 0; unknown 10 |
| DNS remote | 20 | 20 if names resolve on the proxy side, else 0 |

Grades: A ≥ 80, B ≥ 60, C ≥ 40, D below.

## Requirements

Python 3.9+. Standard library only — the SOCKS5 handshake (RFC 1928,
with username/password auth per RFC 1929) is implemented by hand,
because the standard library has no SOCKS client.

## Self-test

`--self-test` runs fully offline (17 checks): proxy-URL parsing, exact
SOCKS5 handshake bytes (no-auth and user/pass), refused-CONNECT errors,
HTTP response parsing (Content-Length and chunked), the HTTP-proxy
CONNECT tunnel plus absolute-URI fallback, anonymity grading,
scoring boundaries, a stubbed end-to-end run (scores 100/A), a dead
proxy (scores 0), a check that credentials never appear in output,
verdict classification (Gemini auth error vs region refusal, Google
redirect to `.hk` vs plain 200, Cloudflare challenge pages), a stubbed
verdicts run covering all six services, a fetch failure degrading to
`blocked`, and a TLS-wrap failure surfacing as `ProxyError`.

## Related work and roadmap

Similar tools cover parts of this: `proxyprobe` (Roam) does liveness /
latency / exit IP / anonymity / geo for a single proxy in one Python
file; `proxy-lane-checker` does TCP / geo / DNSBL checks;
`lmc999/RegionRestrictionCheck` (`check.sh`) does streaming and AI
unlock detection. What this project is building toward, and what none
of those do in one place, is a scorecard driven by a Clash subscription
file, with AI-service verdicts (Gemini / Claude / ChatGPT / YouTube /
GitHub reachability plus "sent to China" detection) at its core.

Roadmap: stage 1 — single-node mode. Stage 2 (this release) — AI
service verdicts. Stage 3 — subscription mode: read a Clash YAML and
score every node in it. Stage 4 — streaming unlocks, scheduled
re-checks, history.

## Limitations

* Geo/ASN data comes from ip-api.com (free tier, no key); if it is
unreachable, the check reports the proxy dead even though the proxy
itself may be fine — the error message says which endpoint failed.
* Latency includes the full request round-trip through the proxy, not
  just TCP connect time.
* Verdicts are a single GET each: a service that is slow or flaky can
  show `blocked` on one run and `ok` on the next — re-run before
  concluding a node is unusable for that service.

## License

MIT.

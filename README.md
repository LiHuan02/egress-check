# egress-check

A single-file, zero-dependency CLI that scores one proxy's **egress
quality**: is this node alive, where does traffic actually come out, does
it leak your real IP, how slow is it, and does DNS leak?

```text
$ python3 egress-check.py socks5://user:pass@host:1080
egress-check  socks5://host:1080
alive        yes
exit IP      203.0.113.7
geo          Los Angeles, United States (US)
ASN          AS12345 Example
ISP          Example ISP
latency      median 120 ms (min 98, max 210; 5 samples)
anonymity    elite — no proxy-identifying headers seen
DNS          remote — proxy was given only the hostname, so the lookup happened on the proxy side
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
python3 egress-check.py --self-test
```

* The proxy URL is `socks5://` or `http(s)://`, with optional
  `user:pass@`. Default ports: 1080 (socks5), 8080 (http). Credentials
  are never printed: reports show only `scheme://host:port`.
* `--samples` sets how many requests the latency median is taken over
  (default 5). `--timeout` sets the per-request timeout in seconds
  (default 10).
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

`--self-test` runs fully offline (12 checks): proxy-URL parsing, exact
SOCKS5 handshake bytes (no-auth and user/pass), refused-CONNECT errors,
HTTP response parsing (Content-Length and chunked), the HTTP-proxy
CONNECT tunnel plus absolute-URI fallback, anonymity grading,
scoring boundaries, a stubbed end-to-end run (scores 100/A), a dead
proxy (scores 0), and a check that credentials never appear in output.

## Related work and roadmap

Similar tools cover parts of this: `proxyprobe` (Roam) does liveness /
latency / exit IP / anonymity / geo for a single proxy in one Python
file; `proxy-lane-checker` does TCP / geo / DNSBL checks;
`lmc999/RegionRestrictionCheck` (`check.sh`) does streaming and AI
unlock detection. What this project is building toward, and what none
of those do in one place, is a scorecard driven by a Clash subscription
file, with AI-service verdicts (Gemini / Claude / ChatGPT / YouTube /
GitHub reachability plus "sent to China" detection) at its core.

Roadmap: stage 1 (this release) — single-node mode. Stage 2 — AI
service verdicts. Stage 3 — subscription mode: read a Clash YAML and
score every node in it. Stage 4 — streaming unlocks, scheduled
re-checks, history.

## Limitations

* Stage 1 checks plain-HTTP endpoints only; HTTPS-target checks (needed
  for some service verdicts) arrive with stage 2.
* Geo/ASN data comes from ip-api.com (free tier, no key); if it is
  unreachable, the check reports the proxy dead even though the proxy
  itself may be fine — the error message says which endpoint failed.
* Latency includes the full request round-trip through the proxy, not
  just TCP connect time.

## License

MIT.

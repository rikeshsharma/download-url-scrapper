# Security and safety controls

## Network destination policy

Applied to **every** HTTP request hop (crawler, probes, robots, sitemaps, adapters,
checksums, reputation) and to **all browser traffic** (navigations, redirects,
subresources, popups, downloads):

* Blocks non-globally-routable destinations: loopback, RFC 1918 private, link-local
  (incl. 169.254.169.254), CGNAT, multicast, reserved, unspecified, documentation
  ranges, IPv6 ULA/link-local, and IPv4 embedded in IPv6 (mapped, 6to4, Teredo,
  NAT64). Well-known metadata names and `localhost`-style suffixes are blocked by name.
* Ports are restricted (`network.allowed_ports`).
* **DNS rebinding**: names are resolved immediately before connecting and the
  connection is made to the validated address (`aiohttp` custom resolver with the
  DNS cache disabled; the browser proxy connects to the address it validated). If any
  answer for a name is disallowed, the whole name is rejected.
* **Redirects** are followed manually and every hop is re-checked (policy, scope,
  robots). In the browser, every hop passes through the proxy.

### Browser egress proxy

Chromium is launched per verification with a context-level proxy pointing at an
in-process filtering proxy, with Chromium's implicit loopback bypass removed
(`<-loopback>`). The proxy resolves and validates each destination, refuses
disallowed ones (`403` + `X-Collector-Blocked`, recorded as
`blocked_destination:*`), and caps bytes per connection and per run *during
transfer*, so oversized browser downloads are cut off rather than written in full.
QUIC and non-proxied WebRTC UDP are disabled by flags so that HTTP traffic cannot
bypass the proxy.

### Controls that require an external proxy or supervisor

The in-process controls are defence in depth, not a sandbox. For production:

* **Run the browser in an isolated network namespace / container** whose only egress
  is this proxy (or an equivalent external egress proxy/firewall that enforces the
  same destination policy). This covers traffic Chromium could originate outside the
  proxy settings (e.g. a future protocol or a browser bug).
* **Process supervision**: CPU/memory/time limits (cgroups, `ulimit`, container
  limits) for the browser and scanner processes, and a watchdog that kills hung
  runs. `max_elapsed_seconds` only stops new work inside this process.
* **Disk quotas** on `data_dir`: byte caps are enforced during transfer and on
  storage, but a filesystem quota is the hard guarantee.
* **Byte caps over HTTPS** count encrypted tunnel bytes (≈ payload + TLS overhead).
* Setting `browser.egress_proxy: false` requires
  `allow_unfiltered_browser_network: true` and must only be done when an external
  egress filter enforces the policy.

## Access controls

robots.txt is always honoured (RFC 9309: 4xx = allowed, 5xx/unreachable = disallowed
for the origin), including for API adapters. `Retry-After` and exponential backoff are
applied; API rate-limit headers are respected. The tool never submits credentials,
solves CAPTCHAs, bypasses paywalls or modifies requests to get around access
controls; 401/403 responses are recorded as failures.

## Browser isolation

Fresh, incognito-like context per verification; no persistent profile, no user data
dir, no personal credentials; service workers blocked; Chromium's OS sandbox on by
default. The browser never opens downloaded files.

## File handling

* Files are never executed, installed, opened in external applications, or rendered
  with macros. Inspection only reads bytes (magic numbers, ZIP central directory,
  TAR headers) and archive members are never extracted to disk.
* Stored under `files/objects/<sha256[:2]>/<sha256>.bin` (content-derived, not
  server-controlled), mode `0400` (no execute bit). Temporary names are random UUIDs.
* Archive inspection is optional and bounded (members, total uncompressed size,
  compression ratio); anything exceeding a bound, encrypted, unsupported or corrupt is
  `unresolved`.
* ClamAV is invoked on the stored path with `--no-summary --stdout --infected`; it
  does not execute the file.

## Secrets and sensitive URLs

* API keys only from environment variables; never written to the DB, logs or outputs.
* Request `Cookie`/`Authorization` values are never recorded; only cookie names.
  `Set-Cookie` values are dropped (names kept).
* Logs (JSON) redact URL credentials and sensitive/opaque query values and secret-like
  keys. Shareable reports redact URLs. Controlled outputs keep exact URLs and flag
  token-bearing ones (`url_has_token`).

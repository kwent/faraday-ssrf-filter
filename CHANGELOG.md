# Changelog

## 0.4.2 (2026-10-24)

- Fix a 0.4.1 regression: a same-host relative redirect over HTTP dropped the pinned `Host` header, because the relative `Location` resolves against the URL already rewritten to the pinned IP

## 0.4.1 (2026-10-24)

- Drop the `Host` header pinned for a previous HTTP hop when a redirect goes to a direct IP address too (it was only dropped for hostname targets)

## 0.4.0 (2026-10-24)

- **Breaking:** raise `MiddlewareOrderError` when `faraday-follow_redirects` or `faraday_middleware`'s `FollowRedirects` is registered after `:ssrf_filter`. In that order redirect targets were never validated, so a public URL redirecting to a private address bypassed the filter
- Drop the `Host` header pinned for a previous HTTP hop when a redirect goes to another host (it was sent unchanged to the new host on HTTP → HTTPS redirects)
- Pin HTTPS requests to the validated IP at connect time with the `Net::HTTP` adapter (including `CONNECT` through an HTTP proxy), closing DNS rebinding between validation and connect. TLS SNI and certificate verification still use the hostname. SOCKS proxies are not pinned
- Correct the README, which said redirect validation worked regardless of middleware ordering

## 0.3.0 (2026-10-18)

- **Breaking:** require Ruby 3.3+ (3.0–3.2 are end-of-life)
- Block `192.88.99.0/24` (6to4 relay anycast, deprecated by RFC 7526) and its IPv6-mapped forms
- Test against Ruby 3.3, 3.4, 4.0 and head
- Pin RubyGems credentials action to a commit SHA; least-privilege CI token
- Run RuboCop in default Rake task

## 0.2.0 (2026-05-18)

- Add gem name autoload (`require 'faraday-ssrf-filter'` now works)
- Add GitHub Actions release workflow with RubyGems trusted publisher
- Improve .gitignore

## 0.1.0 (2026-05-17)

- Initial release
- Block requests to private/reserved IPv4 and IPv6 ranges
- DNS resolution with hostname replacement (HTTP) to prevent DNS rebinding
- TLS SNI preservation for HTTPS requests
- Redirect validation — block 3xx responses pointing to private/reserved IPs
- IPv4-mapped/compatible/translated IPv6 address detection
- NAT64 well-known prefix detection
- Configurable allowlist/denylist
- Custom DNS resolver support
- Scheme validation
- CI with Ruby 3.0-3.4 x Faraday 1/2 matrix

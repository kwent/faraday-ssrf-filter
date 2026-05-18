# Changelog

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

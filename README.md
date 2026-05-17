# Faraday SSRF Filter

[![Gem Version](https://badge.fury.io/rb/faraday-ssrf-filter.svg)](https://rubygems.org/gems/faraday-ssrf-filter)

A [Faraday](https://github.com/lostisland/faraday) middleware that prevents Server-Side Request Forgery (SSRF) attacks by validating resolved IP addresses against known private and reserved IP ranges before allowing requests to proceed.

Inspired by [ssrf_filter](https://github.com/arkadiyt/ssrf_filter) (which uses `Net::HTTP` directly), this gem brings the same level of SSRF protection to any Faraday-based HTTP client.

## Features

- Blocks requests to **all private/reserved IPv4 and IPv6 ranges** (RFC 1918, RFC 6598, loopback, link-local, multicast, etc.)
- Detects **IPv4-mapped/compatible/translated IPv6 addresses** (e.g., `::ffff:127.0.0.1`)
- Detects **NAT64 well-known prefix** addresses (e.g., `64:ff9b::10.0.0.1`)
- **DNS resolution with IP pinning** to prevent DNS rebinding attacks
- Blocks **direct IP address** usage by default
- Configurable **allowlist/denylist** for fine-grained control
- **Custom DNS resolver** support
- **Scheme validation** (only `http`/`https` by default)
- Works with **all Faraday adapters**

## Installation

Add to your Gemfile:

```ruby
gem 'faraday-ssrf-filter'
```

Or install directly:

```bash
gem install faraday-ssrf-filter
```

## Usage

### Basic Usage

```ruby
require 'faraday/ssrf_filter'

conn = Faraday.new(url: 'https://api.example.com') do |f|
  f.request :ssrf_filter
  f.adapter Faraday.default_adapter
end

# Safe requests work normally
response = conn.get('/data')

# Requests to private IPs are blocked
# e.g., if evil.com resolves to 127.0.0.1
# => raises Faraday::SsrfFilter::PrivateIPError
```

### Configuration Options

```ruby
conn = Faraday.new(url: 'https://api.example.com') do |f|
  f.request :ssrf_filter,
    # Allow specific private ranges (e.g., internal services)
    allowlist: ['10.0.0.0/8'],

    # Block specific public ranges
    denylist: ['93.184.216.0/24'],

    # Allow direct IP addresses in URLs (default: false)
    allow_ip_addresses: true,

    # Restrict allowed URI schemes (default: ['http', 'https'])
    allowed_schemes: %w[http https],

    # Custom DNS resolver (default: Resolv.getaddresses)
    resolver: ->(hostname) { Resolv.getaddresses(hostname) }

  f.adapter Faraday.default_adapter
end
```

### Error Handling

All errors inherit from `Faraday::SsrfFilter::SSRFError` (which inherits from `Faraday::Error`):

```ruby
begin
  conn.get('/data')
rescue Faraday::SsrfFilter::PrivateIPError => e
  # Hostname resolved to a private/reserved IP
rescue Faraday::SsrfFilter::DirectIPError => e
  # URL contains a direct IP address (blocked by default)
rescue Faraday::SsrfFilter::InvalidSchemeError => e
  # URI scheme not in allowed list
rescue Faraday::SsrfFilter::DNSResolutionError => e
  # Could not resolve hostname
rescue Faraday::SsrfFilter::SSRFError => e
  # Catch-all for any SSRF error
end
```

## Blocked IP Ranges

### IPv4

| Range | Purpose |
|---|---|
| `0.0.0.0/8` | Current network |
| `10.0.0.0/8` | Private (RFC 1918) |
| `100.64.0.0/10` | Carrier-grade NAT (RFC 6598) |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local (includes cloud metadata endpoints) |
| `172.16.0.0/12` | Private (RFC 1918) |
| `192.0.0.0/24` | IETF protocol assignments |
| `192.0.2.0/24` | TEST-NET-1 |
| `192.168.0.0/16` | Private (RFC 1918) |
| `198.18.0.0/15` | Benchmarking |
| `198.51.100.0/24` | TEST-NET-2 |
| `203.0.113.0/24` | TEST-NET-3 |
| `224.0.0.0/4` | Multicast |
| `240.0.0.0/4` | Reserved |
| `255.255.255.255/32` | Broadcast |

### IPv6

| Range | Purpose |
|---|---|
| `::/128` | Unspecified |
| `::1/128` | Loopback |
| `100::/64` | Discard prefix |
| `2001::/32` | Teredo tunneling |
| `2001:2::/48` | Benchmarking |
| `2001:10::/28` | ORCHID |
| `2001:20::/28` | ORCHIDv2 |
| `2001:db8::/32` | Documentation |
| `2002::/16` | 6to4 tunneling |
| `3fff::/20` | Documentation |
| `5f00::/16` | Segment Routing (SRv6) |
| `fc00::/7` | Unique local |
| `fe80::/10` | Link-local |
| `ff00::/8` | Multicast |
| `64:ff9b:1::/48` | NAT64 local prefix |

Additionally, all IPv4 blacklisted ranges are also blocked in their IPv4-compatible (`::x.x.x.x`), IPv4-mapped (`::ffff:x.x.x.x`), IPv4-translated (`::ffff:0:x.x.x.x`), and NAT64 (`64:ff9b::x.x.x.x`) IPv6 representations.

## How It Works

1. **Scheme validation** — Only `http` and `https` are allowed by default
2. **Direct IP blocking** — URLs with IP addresses instead of hostnames are blocked by default
3. **DNS resolution** — The hostname is resolved to IP addresses using `Resolv.getaddresses`
4. **IP validation** — Each resolved IP is checked against the comprehensive blacklist
5. **Hostname replacement** — The URL hostname is replaced with the validated IP and the `Host` header is set to the original hostname, preventing DNS rebinding (the adapter connects to the validated IP, not a re-resolved address)

## Acknowledgments

This gem is heavily inspired by [ssrf_filter](https://github.com/arkadiyt/ssrf_filter) by [Arkadiy Tetelman](https://github.com/arkadiyt). The comprehensive IP blacklist, IPv4-mapped IPv6 detection, and NAT64 handling are all based on his excellent work. Thank you for building such a thorough and well-tested SSRF protection library for the Ruby ecosystem.

## License

MIT License. See [LICENSE](LICENSE) for details.

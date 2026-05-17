# frozen_string_literal: true

require 'ipaddr'
require 'resolv'
require 'uri'

module Faraday
  module SsrfFilter
    class SSRFError < Faraday::Error; end
    class PrivateIPError < SSRFError; end
    class DirectIPError < SSRFError; end
    class InvalidSchemeError < SSRFError; end
    class DNSResolutionError < SSRFError; end
    class UnsafeRedirectError < SSRFError; end

    class Middleware < Faraday::Middleware
      DEFAULT_SCHEMES = %w[http https].freeze
      REDIRECT_STATUSES = (300..399)

      IPV4_DENYLIST = [
        IPAddr.new('0.0.0.0/8'),
        IPAddr.new('10.0.0.0/8'),
        IPAddr.new('100.64.0.0/10'),
        IPAddr.new('127.0.0.0/8'),
        IPAddr.new('169.254.0.0/16'),
        IPAddr.new('172.16.0.0/12'),
        IPAddr.new('192.0.0.0/24'),
        IPAddr.new('192.0.2.0/24'),
        IPAddr.new('192.168.0.0/16'),
        IPAddr.new('198.18.0.0/15'),
        IPAddr.new('198.51.100.0/24'),
        IPAddr.new('203.0.113.0/24'),
        IPAddr.new('224.0.0.0/4'),
        IPAddr.new('240.0.0.0/4'),
        IPAddr.new('255.255.255.255/32')
      ].freeze

      IPV6_DENYLIST = [
        IPAddr.new('::1/128'),
        IPAddr.new('::/128'),
        IPAddr.new('100::/64'),
        IPAddr.new('2001::/32'),
        IPAddr.new('2001:2::/48'),
        IPAddr.new('2001:10::/28'),
        IPAddr.new('2001:20::/28'),
        IPAddr.new('2001:db8::/32'),
        IPAddr.new('2002::/16'),
        IPAddr.new('3fff::/20'),
        IPAddr.new('5f00::/16'),
        IPAddr.new('fc00::/7'),
        IPAddr.new('fe80::/10'),
        IPAddr.new('ff00::/8'),
        IPAddr.new('64:ff9b:1::/48'),
        *IPV4_DENYLIST.flat_map do |range|
          pfx = range.prefix
          ip = range.to_s
          [
            IPAddr.new("::#{ip}/#{pfx + 96}"),
            IPAddr.new("::ffff:#{ip}/#{pfx + 96}"),
            IPAddr.new("::ffff:0:#{ip}/#{pfx + 96}"),
            IPAddr.new("64:ff9b::#{ip}/#{pfx + 96}")
          ]
        end
      ].freeze

      def initialize(app, options = {})
        super(app)
        @schemes = (options[:allowed_schemes] || DEFAULT_SCHEMES).freeze
        @resolver = options[:resolver] || method(:default_resolver)
        @allow_ip_addresses = options[:allow_ip_addresses] == true
        @allowlist = parse_ip_list(options[:allowlist]).freeze
        @denylist = parse_ip_list(options[:denylist]).freeze
      end

      def call(env)
        validate_and_pin!(env)
        @app.call(env).on_complete { |response_env| validate_redirect!(response_env) }
      end

      private

      def default_resolver(hostname)
        Resolv.getaddresses(hostname)
      end

      def parse_ip_list(list)
        (list || []).map { |r| r.is_a?(IPAddr) ? r : IPAddr.new(r) }
      end

      def validate_and_pin!(env)
        validate_scheme!(env[:url])
        hostname = env[:url].hostname
        addr = parse_ip(hostname)

        if addr
          validate_direct_ip!(addr, hostname)
        else
          resolve_and_pin!(env, hostname)
        end
      end

      def validate_scheme!(uri)
        raise InvalidSchemeError, "URI scheme '#{uri.scheme}' not allowed" unless @schemes.include?(uri.scheme)
      end

      def validate_direct_ip!(addr, hostname)
        raise DirectIPError, "Direct IP addresses are not allowed: #{hostname}" unless @allow_ip_addresses
        raise PrivateIPError, "IP address '#{hostname}' is private/reserved" unless safe_addr?(addr)
      end

      def resolve_and_pin!(env, hostname)
        addresses = Array(@resolver.call(hostname))
        raise DNSResolutionError, "Could not resolve hostname: #{hostname}" if addresses.empty?

        safe_address = addresses.find { |a| safe_ip?(a.to_s) }
        raise PrivateIPError, "Hostname '#{hostname}' resolves to a private/reserved IP address" unless safe_address

        pin_ip!(env, safe_address.to_s, hostname)
      end

      def pin_ip!(env, ip, original_hostname)
        uri = env[:url]
        env[:request_headers] ||= {}
        env[:request_headers]['X-Faraday-SSRF-Original-Host'] = original_hostname
        env[:request_headers]['X-Faraday-SSRF-Resolved-IP'] = ip

        # Only rewrite hostname for HTTP. For HTTPS, rewriting breaks TLS SNI
        # and certificate verification since the adapter would negotiate TLS
        # with the IP address instead of the original hostname.
        return unless uri.scheme == 'http'

        env[:request_headers]['Host'] = normalized_host(uri)
        env[:url] = uri.dup.tap { |u| u.hostname = ip }
      end

      def validate_redirect!(env)
        return unless REDIRECT_STATUSES.cover?(env[:status])

        location = env[:response_headers]&.[]('location')
        return if location.nil? || location.empty?

        uri = resolve_redirect_uri(location, env[:url])
        validate_redirect_target!(uri)
      end

      def resolve_redirect_uri(location, original_uri)
        uri = URI.parse(location)
        return uri if uri.host

        URI.join("#{original_uri.scheme}://#{original_uri.host}:#{original_uri.port}", location)
      rescue URI::InvalidURIError
        raise UnsafeRedirectError, "Invalid redirect location: #{location}"
      end

      def validate_redirect_target!(uri)
        raise UnsafeRedirectError, "Redirect to disallowed scheme: #{uri.scheme}" unless @schemes.include?(uri.scheme)

        hostname = uri.hostname || uri.host
        return unless hostname

        addr = parse_ip(hostname)
        if addr
          raise UnsafeRedirectError, "Redirect to private IP: #{hostname}" unless safe_addr?(addr)
        else
          validate_redirect_hostname!(hostname)
        end
      end

      def validate_redirect_hostname!(hostname)
        addresses = Array(@resolver.call(hostname))
        raise UnsafeRedirectError, "Cannot resolve redirect hostname: #{hostname}" if addresses.empty?

        safe = addresses.any? { |a| safe_ip?(a.to_s) }
        raise UnsafeRedirectError, "Redirect to '#{hostname}' resolves to a private IP" unless safe
      end

      def normalized_host(uri)
        host = uri.hostname
        port = uri.port
        return host if port.nil?
        return host if uri.scheme == 'http' && port == 80
        return host if uri.scheme == 'https' && port == 443

        "#{host}:#{port}"
      end

      def parse_ip(hostname)
        IPAddr.new(hostname)
      rescue IPAddr::InvalidAddressError
        nil
      end

      def safe_ip?(ip_string)
        safe_addr?(IPAddr.new(ip_string))
      rescue IPAddr::InvalidAddressError
        false
      end

      def safe_addr?(addr)
        return true if @allowlist.any? { |range| range.include?(addr) }
        return false if @denylist.any? { |range| range.include?(addr) }

        !unsafe_ip?(addr)
      end

      def unsafe_ip?(addr)
        if addr.ipv4?
          IPV4_DENYLIST.any? { |range| range.include?(addr) }
        elsif addr.ipv6?
          IPV6_DENYLIST.any? { |range| range.include?(addr) }
        else
          true
        end
      end
    end
  end
end

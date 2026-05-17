# frozen_string_literal: true

require 'ipaddr'
require 'resolv'

module Faraday
  module SsrfFilter
    class SSRFError < Faraday::Error; end
    class PrivateIPError < SSRFError; end
    class DirectIPError < SSRFError; end
    class InvalidSchemeError < SSRFError; end
    class DNSResolutionError < SSRFError; end

    class Middleware < Faraday::Middleware
      DEFAULT_SCHEMES = %w[http https].freeze

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
        @app.call(env)
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
        env[:request_headers]['Host'] = normalized_host(uri)
        env[:request_headers]['X-Faraday-SSRF-Original-Host'] = original_hostname
        env[:url] = uri.dup.tap { |u| u.hostname = ip }
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

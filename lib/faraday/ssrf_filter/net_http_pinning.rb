# frozen_string_literal: true

module Faraday
  module SsrfFilter
    # Makes the Net::HTTP adapter connect to the IP the filter validated
    # instead of resolving the hostname again, while TLS SNI and certificate
    # verification keep using the hostname. Through an HTTP proxy the CONNECT
    # request targets the pinned IP too. SOCKS proxies are left unpinned so
    # the request still goes through the proxy.
    module NetHttpPinning
      ENV_KEY = :ssrf_filter_pinned_ip

      def self.install
        return unless defined?(Faraday::Adapter::NetHttp)
        return if Faraday::Adapter::NetHttp.ancestors.include?(self)

        Faraday::Adapter::NetHttp.prepend(self)
      end

      def self.pin(env, ip)
        env[ENV_KEY] = ip
      end

      def self.connect_ip(env)
        env[ENV_KEY] unless socks_proxy?(env[:request] && env[:request][:proxy])
      end

      def self.socks_proxy?(proxy)
        proxy && proxy[:uri].scheme == 'socks'
      end

      private

      def net_http_connection(env)
        super.tap do |http|
          ip = NetHttpPinning.connect_ip(env)
          http.ipaddr = ip if ip && http.respond_to?(:ipaddr=)
        end
      end
    end
  end
end

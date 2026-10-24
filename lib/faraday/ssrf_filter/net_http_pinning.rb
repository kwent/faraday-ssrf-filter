# frozen_string_literal: true

module Faraday
  module SsrfFilter
    # Makes the Net::HTTP adapter connect to the IP the filter validated
    # instead of resolving the hostname again, while TLS SNI and certificate
    # verification keep using the hostname. Through an HTTP proxy the CONNECT
    # request targets the pinned IP too.
    module NetHttpPinning
      CONTEXT_KEY = :ssrf_filter_pinned_ip

      def self.install
        return unless defined?(Faraday::Adapter::NetHttp)
        return if Faraday::Adapter::NetHttp.ancestors.include?(self)

        Faraday::Adapter::NetHttp.prepend(self)
      end

      def self.pin(env, ip)
        request = env[:request]
        return unless request

        context = request[:context]
        return if context && !context.is_a?(Hash)

        context = (context || {}).dup
        ip ? context[CONTEXT_KEY] = ip : context.delete(CONTEXT_KEY)
        request[:context] = context
      end

      def self.pinned_ip(env)
        context = env[:request] && env[:request][:context]
        context[CONTEXT_KEY] if context.is_a?(Hash)
      end

      private

      def net_http_connection(env)
        super.tap do |http|
          ip = NetHttpPinning.pinned_ip(env)
          http.ipaddr = ip if ip && http.respond_to?(:ipaddr=)
        end
      end
    end
  end
end

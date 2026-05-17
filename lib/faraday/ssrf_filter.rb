# frozen_string_literal: true

require 'faraday'
require_relative 'ssrf_filter/middleware'
require_relative 'ssrf_filter/version'

module Faraday
  module SsrfFilter
    Faraday::Request.register_middleware(ssrf_filter: Faraday::SsrfFilter::Middleware)
  end
end

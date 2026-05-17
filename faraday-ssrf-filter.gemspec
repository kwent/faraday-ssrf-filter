# frozen_string_literal: true

require_relative 'lib/faraday/ssrf_filter/version'

Gem::Specification.new do |spec|
  spec.name          = 'faraday-ssrf-filter'
  spec.version       = Faraday::SsrfFilter::VERSION
  spec.authors       = ['Quentin Rousseau']
  spec.email         = ['contact@quent.in']

  spec.summary       = 'Faraday middleware to prevent SSRF attacks'
  spec.description = 'A Faraday middleware that prevents Server-Side Request Forgery (SSRF) ' \
                     'attacks by validating resolved IP addresses against known private and ' \
                     'reserved IP ranges before allowing the request to proceed.'
  spec.homepage      = 'https://github.com/kwent/faraday-ssrf-filter'
  spec.license       = 'MIT'

  spec.required_ruby_version = '>= 3.0.0'

  spec.metadata['homepage_uri']    = spec.homepage
  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['changelog_uri']   = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = Dir['lib/**/*', 'LICENSE', 'README.md', 'CHANGELOG.md']
               .reject { |f| File.directory?(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'faraday', '>= 1.0', '< 3'
end

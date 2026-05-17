# frozen_string_literal: true

RSpec.describe Faraday::SsrfFilter::Middleware do
  let(:resolver) { ->(_hostname) { resolved_ips } }
  let(:resolved_ips) { ['93.184.216.34'] }
  let(:stubs) { Faraday::Adapter::Test::Stubs.new }

  let(:conn) do
    Faraday.new(url: 'http://example.com') do |f|
      f.request :ssrf_filter, **middleware_options
      f.adapter :test, stubs
    end
  end

  let(:middleware_options) { { resolver: resolver } }

  after { stubs.verify_stubbed_calls }

  describe 'public IP addresses' do
    it 'allows requests to public IPs' do
      stubs.get('/') { [200, {}, 'ok'] }
      response = conn.get('/')
      expect(response.status).to eq(200)
      expect(response.body).to eq('ok')
    end

    it 'replaces hostname with resolved IP in URL' do
      stubs.get('/') do |env|
        expect(env.url.hostname).to eq('93.184.216.34')
        [200, {}, 'ok']
      end
      conn.get('/')
    end

    it 'sets Host header to original hostname' do
      stubs.get('/') do |env|
        expect(env.request_headers['Host']).to eq('example.com')
        [200, {}, 'ok']
      end
      conn.get('/')
    end

    it 'preserves original hostname in X-Faraday-SSRF-Original-Host header' do
      stubs.get('/') do |env|
        expect(env.request_headers['X-Faraday-SSRF-Original-Host']).to eq('example.com')
        [200, {}, 'ok']
      end
      conn.get('/')
    end

    it 'includes non-standard port in Host header' do
      custom_stubs = Faraday::Adapter::Test::Stubs.new
      c = Faraday.new(url: 'http://example.com:8080') do |f|
        f.request :ssrf_filter, resolver: resolver
        f.adapter :test, custom_stubs
      end
      custom_stubs.get('/') do |env|
        expect(env.request_headers['Host']).to eq('example.com:8080')
        [200, {}, 'ok']
      end
      c.get('/')
      custom_stubs.verify_stubbed_calls
    end

    it 'selects first safe IP when multiple resolved' do
      resolved = ['10.0.0.1', '93.184.216.34']
      custom_resolver = ->(_) { resolved }
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver
        f.adapter :test, stubs
      end
      stubs.get('/') do |env|
        expect(env.url.hostname).to eq('93.184.216.34')
        [200, {}, 'ok']
      end
      c.get('/')
    end
  end

  describe 'IPv4 private ranges' do
    [
      ['0.0.0.0', '0.0.0.0/8'],
      ['10.0.0.1', '10.0.0.0/8'],
      ['100.64.0.1', '100.64.0.0/10'],
      ['127.0.0.1', '127.0.0.0/8'],
      ['169.254.169.254', '169.254.0.0/16 (AWS metadata)'],
      ['172.16.0.1', '172.16.0.0/12'],
      ['192.0.0.1', '192.0.0.0/24'],
      ['192.0.2.1', '192.0.2.0/24'],
      ['192.168.1.1', '192.168.0.0/16'],
      ['198.18.0.1', '198.18.0.0/15'],
      ['198.51.100.1', '198.51.100.0/24'],
      ['203.0.113.1', '203.0.113.0/24'],
      ['224.0.0.1', '224.0.0.0/4 (multicast)'],
      ['240.0.0.1', '240.0.0.0/4'],
      ['255.255.255.255', 'broadcast']
    ].each do |ip, range|
      it "blocks #{ip} (#{range})" do
        custom_resolver = ->(_) { [ip] }
        c = Faraday.new(url: 'http://example.com') do |f|
          f.request :ssrf_filter, resolver: custom_resolver
          f.adapter :test, stubs
        end
        expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
      end
    end
  end

  describe 'IPv6 private ranges' do
    [
      ['::1', 'loopback'],
      ['::', 'unspecified'],
      ['fc00::1', 'unique local'],
      ['fe80::1', 'link-local'],
      ['ff00::1', 'multicast'],
      ['2001:db8::1', 'documentation'],
      ['2001::1', 'Teredo'],
      ['2002::1', '6to4']
    ].each do |ip, desc|
      it "blocks #{ip} (#{desc})" do
        custom_resolver = ->(_) { [ip] }
        c = Faraday.new(url: 'http://example.com') do |f|
          f.request :ssrf_filter, resolver: custom_resolver
          f.adapter :test, stubs
        end
        expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
      end
    end
  end

  describe 'IPv4-mapped IPv6 addresses' do
    it 'blocks ::ffff:127.0.0.1 (IPv4-mapped)' do
      custom_resolver = ->(_) { ['::ffff:127.0.0.1'] }
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
    end

    it 'blocks ::ffff:10.0.0.1 (IPv4-mapped)' do
      custom_resolver = ->(_) { ['::ffff:10.0.0.1'] }
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
    end

    it 'blocks ::ffff:169.254.169.254 (IPv4-mapped)' do
      custom_resolver = ->(_) { ['::ffff:169.254.169.254'] }
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
    end
  end

  describe 'IPv4-compatible IPv6 addresses' do
    it 'blocks ::10.0.0.1 (IPv4-compatible, deprecated)' do
      custom_resolver = ->(_) { ['::10.0.0.1'] }
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
    end
  end

  describe 'IPv4-translated IPv6 addresses' do
    it 'blocks ::ffff:0:10.0.0.1 (IPv4-translated)' do
      custom_resolver = ->(_) { ['::ffff:0:10.0.0.1'] }
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
    end
  end

  describe 'NAT64 addresses' do
    it 'blocks 64:ff9b::10.0.0.1' do
      custom_resolver = ->(_) { ['64:ff9b::10.0.0.1'] }
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
    end

    it 'blocks 64:ff9b::127.0.0.1' do
      custom_resolver = ->(_) { ['64:ff9b::127.0.0.1'] }
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
    end

    it 'allows 64:ff9b:: with public IPv4' do
      custom_resolver = ->(_) { ['64:ff9b::93.184.216.34'] }
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver
        f.adapter :test, stubs
      end
      stubs.get('/') { [200, {}, 'ok'] }
      response = c.get('/')
      expect(response.status).to eq(200)
    end
  end

  describe 'scheme validation' do
    it 'blocks non-http/https schemes' do
      c = Faraday.new(url: 'ftp://example.com') do |f|
        f.request :ssrf_filter, resolver: resolver
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::InvalidSchemeError)
    end

    it 'allows custom schemes when configured' do
      c = Faraday.new(url: 'ftp://example.com') do |f|
        f.request :ssrf_filter, resolver: resolver, allowed_schemes: %w[http https ftp]
        f.adapter :test, stubs
      end
      stubs.get('/') { [200, {}, 'ok'] }
      response = c.get('/')
      expect(response.status).to eq(200)
    end
  end

  describe 'direct IP addresses' do
    it 'blocks direct IP addresses by default with DirectIPError' do
      c = Faraday.new(url: 'http://93.184.216.34') do |f|
        f.request :ssrf_filter
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::DirectIPError)
    end

    it 'allows direct public IPs when allow_ip_addresses is true' do
      c = Faraday.new(url: 'http://93.184.216.34') do |f|
        f.request :ssrf_filter, allow_ip_addresses: true
        f.adapter :test, stubs
      end
      stubs.get('/') { [200, {}, 'ok'] }
      response = c.get('/')
      expect(response.status).to eq(200)
    end

    it 'blocks direct private IPs even when allow_ip_addresses is true' do
      c = Faraday.new(url: 'http://127.0.0.1') do |f|
        f.request :ssrf_filter, allow_ip_addresses: true
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
    end
  end

  describe 'DNS resolution failure' do
    it 'raises on unresolvable hostname' do
      empty_resolver = ->(_) { [] }
      c = Faraday.new(url: 'http://doesnotexist.invalid') do |f|
        f.request :ssrf_filter, resolver: empty_resolver
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::DNSResolutionError)
    end
  end

  describe 'allowlist' do
    it 'allows requests to allowlisted private IPs' do
      custom_resolver = ->(_) { ['10.0.0.1'] }
      c = Faraday.new(url: 'http://internal.example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver, allowlist: ['10.0.0.0/8']
        f.adapter :test, stubs
      end
      stubs.get('/') { [200, {}, 'ok'] }
      response = c.get('/')
      expect(response.status).to eq(200)
    end

    it 'still blocks non-allowlisted private IPs' do
      custom_resolver = ->(_) { ['192.168.1.1'] }
      c = Faraday.new(url: 'http://internal.example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver, allowlist: ['10.0.0.0/8']
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
    end
  end

  describe 'denylist' do
    it 'blocks requests to denylisted public IPs' do
      custom_resolver = ->(_) { ['93.184.216.34'] }
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver, denylist: ['93.184.216.0/24']
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
    end
  end

  describe 'custom resolver' do
    it 'uses provided resolver' do
      called = false
      custom_resolver = lambda do |hostname|
        called = true
        expect(hostname).to eq('example.com')
        ['93.184.216.34']
      end
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver
        f.adapter :test, stubs
      end
      stubs.get('/') { [200, {}, 'ok'] }
      c.get('/')
      expect(called).to be true
    end
  end

  describe 'all resolved IPs are private' do
    it 'raises when all IPs are private' do
      custom_resolver = ->(_) { ['10.0.0.1', '192.168.1.1', '172.16.0.1'] }
      c = Faraday.new(url: 'http://example.com') do |f|
        f.request :ssrf_filter, resolver: custom_resolver
        f.adapter :test, stubs
      end
      expect { c.get('/') }.to raise_error(Faraday::SsrfFilter::PrivateIPError)
    end
  end

  describe 'error hierarchy' do
    it 'all errors inherit from SSRFError' do
      expect(Faraday::SsrfFilter::PrivateIPError).to be < Faraday::SsrfFilter::SSRFError
      expect(Faraday::SsrfFilter::DirectIPError).to be < Faraday::SsrfFilter::SSRFError
      expect(Faraday::SsrfFilter::InvalidSchemeError).to be < Faraday::SsrfFilter::SSRFError
      expect(Faraday::SsrfFilter::DNSResolutionError).to be < Faraday::SsrfFilter::SSRFError
    end

    it 'SSRFError inherits from Faraday::Error' do
      expect(Faraday::SsrfFilter::SSRFError).to be < Faraday::Error
    end
  end

  describe 'HTTP methods' do
    %i[get post put patch delete head options].each do |method|
      it "works with #{method.upcase} requests" do
        stubs.send(method, '/') { [200, {}, 'ok'] }
        response = conn.send(method, '/')
        expect(response.status).to eq(200)
      end
    end
  end
end

# frozen_string_literal: true

require 'openssl'
require 'socket'
require 'tempfile'

RSpec.describe Faraday::SsrfFilter::NetHttpPinning do
  let(:public_ip) { '93.184.216.34' }
  let(:resolver) { ->(_hostname) { [public_ip] } }
  let(:stubs) { Faraday::Adapter::Test::Stubs.new }

  def test_connection(url)
    Faraday.new(url: url) do |f|
      f.request :ssrf_filter, resolver: resolver
      f.adapter :test, stubs
    end
  end

  describe 'pinned IP' do
    after { stubs.verify_stubbed_calls }

    it 'stores the validated IP for HTTPS requests' do
      stubs.get('/') do |env|
        expect(described_class.connect_ip(env)).to eq(public_ip)
        [200, {}, 'ok']
      end
      test_connection('https://example.com').get('/')
    end

    it 'does not store a pinned IP for HTTP requests' do
      stubs.get('/') do |env|
        expect(described_class.connect_ip(env)).to be_nil
        [200, {}, 'ok']
      end
      test_connection('http://example.com').get('/')
    end

    it 'pins regardless of the caller request context' do
      stubs.get('/') do |env|
        expect(described_class.connect_ip(env)).to eq(public_ip)
        expect(env.request.context).to eq('caller-context')
        [200, {}, 'ok']
      end
      test_connection('https://example.com').get('/') { |req| req.options.context = 'caller-context' }
    end

    it 'clears a stale pinned IP when an HTTPS request is followed by an HTTP one' do
      stubs.get('https://a.example.com/') { [302, { 'Location' => 'http://b.example.com/' }, ''] }
      stubs.get('/') do |env|
        expect(described_class.connect_ip(env)).to be_nil
        [200, {}, 'ok']
      end
      conn = Faraday.new(url: 'https://a.example.com') do |f|
        f.response :follow_redirects
        f.request :ssrf_filter, resolver: resolver
        f.adapter :test, stubs
      end
      expect(conn.get('/').body).to eq('ok')
    end

    it 'leaves requests through a SOCKS proxy unpinned' do
      stubs.get('/') do |env|
        expect(described_class.connect_ip(env)).to be_nil
        [200, {}, 'ok']
      end
      conn = Faraday.new(url: 'https://example.com', proxy: 'socks://127.0.0.1:1080') do |f|
        f.request :ssrf_filter, resolver: resolver
        f.adapter :test, stubs
      end
      conn.get('/')
    end
  end

  describe 'Net::HTTP adapter' do
    let(:hostname) { 'rebind.test' }
    let(:resolver) { ->(_hostname) { ['127.0.0.1'] } }
    let(:key) { OpenSSL::PKey::RSA.new(2048) }
    let(:cert) { self_signed_cert(key, hostname) }
    let(:ca_file) do
      Tempfile.new(['ca', '.pem']).tap do |file|
        file.write(cert.to_pem)
        file.flush
      end
    end
    let(:server_names) { Queue.new }
    let(:connect_lines) { Queue.new }
    let(:tls_server) { TCPServer.new('127.0.0.1', 0) }
    let(:tls_port) { tls_server.addr[1] }

    around do |example|
      WebMock.disable!
      example.run
    ensure
      WebMock.enable!
    end

    before { serve_tls_once }

    after do
      tls_server.close
      ca_file.close!
    end

    def self_signed_cert(key, name)
      OpenSSL::X509::Certificate.new.tap do |c|
        c.version = 2
        c.serial = 1
        c.subject = c.issuer = OpenSSL::X509::Name.parse("/CN=#{name}")
        c.public_key = key.public_key
        c.not_before = Time.now - 60
        c.not_after = Time.now + 3600
        ext = OpenSSL::X509::ExtensionFactory.new(c, c)
        c.add_extension(ext.create_extension('subjectAltName', "DNS:#{name}"))
        c.add_extension(ext.create_extension('basicConstraints', 'CA:TRUE', true))
        c.sign(key, OpenSSL::Digest.new('SHA256'))
      end
    end

    def serve_tls_once
      context = OpenSSL::SSL::SSLContext.new
      context.cert = cert
      context.key = key
      context.servername_cb = lambda do |(ssl, name)|
        server_names << name
        ssl.context
      end
      ssl_server = OpenSSL::SSL::SSLServer.new(tls_server, context)
      Thread.new do
        socket = ssl_server.accept
        nil while (line = socket.gets) && line != "\r\n"
        socket.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        socket.close
      rescue OpenSSL::SSL::SSLError, IOError, Errno::ECONNRESET
        nil
      end
    end

    def serve_connect_proxy_once(proxy_server)
      Thread.new do
        client = proxy_server.accept
        connect_lines << client.gets.strip
        nil while (line = client.gets) && line != "\r\n"
        upstream = TCPSocket.new('127.0.0.1', tls_port)
        client.write("HTTP/1.1 200 Connection established\r\n\r\n")
        pipe(client, upstream)
      rescue IOError, Errno::ECONNRESET
        nil
      end
    end

    def pipe(left, right)
      sockets = [left, right]
      loop do
        IO.select(sockets)[0].each do |from|
          to = from == left ? right : left
          to.write(from.readpartial(16_384))
        end
      end
    rescue IOError, Errno::ECONNRESET
      sockets.each(&:close)
    end

    def pinned_connection(**options)
      Faraday.new(url: "https://#{hostname}:#{tls_port}", ssl: { ca_file: ca_file.path }, **options) do |f|
        f.request :ssrf_filter, resolver: resolver, allowlist: ['127.0.0.1/32']
        f.adapter :net_http
      end
    end

    it 'connects to the validated IP and keeps the hostname for SNI and certificate verification' do
      response = pinned_connection.get('/')

      expect(response.body).to eq('ok')
      expect(server_names.pop).to eq(hostname)
    end

    it 'sends CONNECT for the validated IP through an HTTP proxy' do
      proxy_server = TCPServer.new('127.0.0.1', 0)
      serve_connect_proxy_once(proxy_server)

      response = pinned_connection(proxy: "http://127.0.0.1:#{proxy_server.addr[1]}").get('/')

      expect(response.body).to eq('ok')
      expect(connect_lines.pop).to eq("CONNECT 127.0.0.1:#{tls_port} HTTP/1.1")
      expect(server_names.pop).to eq(hostname)
    ensure
      proxy_server&.close
    end

    it 'fails without pinning because the hostname does not resolve' do
      http = Net::HTTP.new(hostname, tls_port)
      http.use_ssl = true
      http.ca_file = ca_file.path

      expect { http.get('/') }.to raise_error(SocketError)
    end
  end
end

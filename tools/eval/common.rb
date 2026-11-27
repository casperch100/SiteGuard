# encoding: utf-8
# 評估工具共用的函式：網域正規化、可註冊網域、RDAP 查詢、HTTP 下載
require 'net/http'
require 'uri'
require 'json'
require 'date'
require 'fileutils'
require 'zlib'
require 'stringio'

module EvalCommon
  module_function

  # 常見的二層公眾後綴（和 src/lib/risk.js 的 MULTI_PART_SUFFIXES 一致，再補幾個常見的）
  # 和 src/lib/risk.js 的 MULTI_PART_SUFFIXES 保持一致
  MULTI_PART_SUFFIXES = %w[com.tw net.tw org.tw gov.tw edu.tw idv.tw co.uk co.jp com.cn com.hk com.sg com.au com.br co.in co.kr].freeze

  # 任何人都能申請子網域的共用平台：子網域是詐騙網站，不代表平台本身是。
  # 這類網址的「網域年齡」是平台的年齡，沒有參考價值，評估時分開統計。
  PLATFORMS = %w[
    blogspot.com web.app firebaseapp.com vercel.app netlify.app github.io pages.dev workers.dev weebly.com
    wixsite.com square.site godaddysites.com webflow.io glitch.me herokuapp.com azurewebsites.net r2.dev
    framer.app framer.website canva.site my.canva.site onrender.com replit.app repl.co wordpress.com
    mystrikingly.com jimdosite.com ipfs.dweb.link gitbook.io notion.site webcindario.com 000webhostapp.com
    duckdns.org ngrok-free.app ngrok.io trycloudflare.com surge.sh myshopify.com wcomhost.com
    sites.google.com docs.google.com forms.gle storage.googleapis.com firebasestorage.googleapis.com
    s3.amazonaws.com cloudfront.net appspot.com typedream.app carrd.co webnode.page
  ].freeze

  def normalize_host(s)
    h = s.to_s.strip.downcase
    h = h.sub(%r{\A[a-z][a-z0-9+.-]*://}, '').sub(/\A[^@\/]*@/, '').sub(%r{[/?#:\\\s].*\z}, '').sub(/\.\z/, '').sub(/\Awww\./, '')
    h =~ /\A[a-z0-9-]+(\.[a-z0-9-]+)+\z/ ? h : nil
  end

  # 回傳 [可註冊網域, 是否為共用平台的子網域]
  def registrable(host)
    # 最長的平台後綴優先（例如 my.canva.site 先於 canva.site），和 src/lib/risk.js 相同
    p = PLATFORMS.select { |x| host.end_with?('.' + x) }.max_by(&:length)
    return [host.split('.').last(p.count('.') + 2).join('.'), true] if p
    labels = host.split('.')
    two = labels.last(2).join('.')
    n = MULTI_PART_SUFFIXES.include?(two) && labels.size >= 3 ? 3 : 2
    [labels.last(n).join('.'), false]
  end

  def roc_month_to_iso(ym)
    return nil unless ym.to_s =~ /\A(\d{2,3})(\d{2})\z/
    Date.new(Regexp.last_match(1).to_i + 1911, Regexp.last_match(2).to_i, 1).iso8601
  end

  def http_get(url, headers = {}, limit = 6)
    http_get_raw(url, headers, limit, false)
  end

  # 下載二進位檔（例如 zip），不轉換文字編碼
  def http_get_binary(url, headers = {}, limit = 6)
    http_get_raw(url, headers, limit, true)
  end

  def http_get_raw(url, headers, limit, binary)
    uri = URI(url)
    limit.times do
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: 15, read_timeout: 120) do |http|
        req = Net::HTTP::Get.new(uri)
        req['Accept-Encoding'] = binary ? 'identity' : 'gzip'
        headers.each { |k, v| req[k] = v }
        http.request(req)
      end
      if res.is_a?(Net::HTTPRedirection)
        uri = URI.join(uri.to_s, res['location'])
        next
      end
      raise "HTTP #{res.code} #{uri.host}" unless res.is_a?(Net::HTTPSuccess)
      body = res.body.to_s.b
      return body if binary
      body = Zlib::GzipReader.new(StringIO.new(body)).read if res['content-encoding'] == 'gzip' || body.byteslice(0, 2) == "\x1f\x8b".b
      return body.force_encoding('UTF-8').scrub
    end
    raise "轉址次數過多：#{url}"
  end

  # IANA 的 RDAP bootstrap：各頂級網域該向哪個註冊局查詢
  def rdap_bootstrap
    @rdap_bootstrap ||= begin
      data = JSON.parse(http_get('https://data.iana.org/rdap/dns.json'))
      map = {}
      data['services'].each { |tlds, urls| tlds.each { |t| map[t.downcase] = urls.find { |u| u.start_with?('https') } || urls.first } }
      map
    end
  end

  # 回傳 [狀態, 註冊日期]；狀態：ok / no_date / not_found / no_rdap（該頂級網域不支援 RDAP）/ error
  def rdap_lookup(domain)
    tld = domain.split('.').last
    base = rdap_bootstrap[tld]
    return ['no_rdap', nil] unless base
    uri = URI.join(base.end_with?('/') ? base : base + '/', "domain/#{domain}")
    4.times do
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: 10, read_timeout: 20) do |http|
        req = Net::HTTP::Get.new(uri)
        req['Accept'] = 'application/rdap+json'
        http.request(req)
      end
      case res
      when Net::HTTPRedirection then uri = URI.join(uri.to_s, res['location'])
      when Net::HTTPNotFound then return ['not_found', nil]
      when Net::HTTPTooManyRequests then sleep 3
      when Net::HTTPSuccess
        ev = (JSON.parse(res.body)['events'] || []).find { |e| e['eventAction'] == 'registration' }
        return ev ? ['ok', Date.parse(ev['eventDate'][0, 10])] : ['no_date', nil]
      else return ["http_#{res.code}", nil]
      end
    end
    ['error', nil]
  rescue StandardError => e
    ['error', nil].tap { warn "RDAP #{domain}: #{e.class}" if ENV['DEBUG'] }
  end

  def rdap_lookup_many(domains, threads: 4)
    rdap_bootstrap # 先載入，避免多執行緒重複下載
    queue = Queue.new
    domains.each { |d| queue << d }
    out = {}
    lock = Mutex.new
    Array.new(threads) do
      Thread.new do
        while (d = (queue.pop(true) rescue nil))
          r = rdap_lookup(d)
          lock.synchronize { out[d] = r }
          sleep 0.2
        end
      end
    end.each(&:join)
    out
  end
end

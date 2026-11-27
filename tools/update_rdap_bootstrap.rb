# encoding: utf-8
# 從 IANA 下載 RDAP bootstrap（各頂級網域該向哪個註冊局查詢註冊資料），
# 轉成擴充功能內建的對照表，讓擴充功能直接向註冊局查詢，不經過任何第三方。
#
#   ruby -Ku tools/update_rdap_bootstrap.rb
#
# 輸出：src/data/rdap-bootstrap.json  { "generatedAt": ..., "tlds": { "com": "https://rdap.verisign.com/com/v1/", ... } }
require 'json'
require 'net/http'
require 'uri'

ROOT = File.expand_path('..', __dir__)
OUT = File.join(ROOT, 'src/data/rdap-bootstrap.json')
SRC = 'https://data.iana.org/rdap/dns.json'

data = JSON.parse(Net::HTTP.get(URI(SRC)))
tlds = {}
data['services'].each do |names, urls|
  url = urls.find { |u| u.start_with?('https://') } # 只用 HTTPS
  next unless url
  url += '/' unless url.end_with?('/')
  names.each { |t| tlds[t.downcase] = url }
end

out = {
  'source' => SRC,
  'publication' => data['publication'],
  'generatedAt' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
  'tlds' => tlds.sort.to_h,
}
File.write(OUT, JSON.generate(out) + "\n")
hosts = tlds.values.map { |u| URI(u).host }.uniq
puts "完成：#{tlds.size} 個頂級網域、#{hosts.size} 個註冊局 RDAP 伺服器（IANA 發布日期 #{data['publication']}）"
puts "  .com → #{tlds['com']}"
puts "  .tw  → #{tlds['tw']}"
puts "  .shop → #{tlds['shop']}"
puts "  #{OUT}（#{File.size(OUT)} bytes）"

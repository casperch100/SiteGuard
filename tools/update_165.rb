# encoding: utf-8
# 下載 165 反詐騙諮詢專線的公開資料，轉成擴充功能內建的名單快照。
#
#   ruby -Ku tools/update_165.rb
#
# 產生：
#   src/data/165-blocklist.txt   每行「主機名稱<TAB>分類代碼」
#   src/data/165-meta.json       分類清單、資料來源、資料月份、筆數
#
# 資料來源（政府資料開放授權條款第 1 版）：
#   - 165反詐騙諮詢專線_遭停止解析涉詐網站  https://data.gov.tw/dataset/176455（每月更新）
#   - 165反詐騙諮詢專線_假投資(博弈)網站    https://data.gov.tw/dataset/160055（已停止更新，保留歷史資料）
require 'csv'
require 'json'
require 'net/http'
require 'uri'

ROOT = File.expand_path('..', __dir__)
OUT_LIST = File.join(ROOT, 'src/data/165-blocklist.txt')
OUT_META = File.join(ROOT, 'src/data/165-meta.json')
RULES = File.join(ROOT, 'src/data/rules.js')

SUSPENDED_URL = 'https://opdadm.moi.gov.tw/api/v1/no-auth/resource/api/dataset/29E8E643-88ED-4952-B21E-BD42A3B7108C/resource/01EFB21E-DB91-4EDF-843F-F45923BBFA1D/download'
INVEST_URL = 'https://opdadm.moi.gov.tw/api/v1/no-auth/resource/api/dataset/033197D4-70F4-45EB-9FB8-6D83532B999A/resource/A00B1802-6A4A-42B4-B842-B66A2D937DAE/download'

# 和 src/lib/blocklist.js 的 normalizeHost 保持一致
def normalize_host(s)
  h = s.to_s.strip.downcase
  h = h.sub(%r{\A[a-z][a-z0-9+.-]*://}, '').sub(%r{[/?#:\\\s].*\z}, '').sub(/\.\z/, '').sub(/\Awww\./, '')
  h =~ /\A[a-z0-9-]+(\.[a-z0-9-]+)+\z/ ? h : nil
end

def download(url)
  uri = URI(url)
  5.times do
    res = Net::HTTP.get_response(uri)
    return res.body.force_encoding('UTF-8') if res.is_a?(Net::HTTPSuccess)
    raise "下載失敗：#{res.code} #{url}" unless res.is_a?(Net::HTTPRedirection)
    uri = URI(res['location'])
  end
  raise "轉址次數過多：#{url}"
end

# 原始資料中的錯字與無意義分類（和 src/lib/blocklist.js 的 SECTOR_FIX 保持一致）
SECTOR_FIX = { '金融保線' => '金融保險', '金融保健' => '金融保險', '不詳' => '' }.freeze

def sector_label(sector)
  s = sector.to_s.strip
  s = SECTOR_FIX.fetch(s, s)
  s.empty? ? '涉詐網站' : "涉詐網站（#{s}）"
end

def roc_month_to_label(ym)
  return nil unless ym.to_s =~ /\A(\d{2,3})(\d{2})\z/
  format('%d/%02d', Regexp.last_match(1).to_i + 1911, Regexp.last_match(2).to_i)
end

# 白名單上的網域不列入，避免誤擋
allow = File.read(RULES)[/ALLOWLIST\s*=\s*new Set\(\[(.*?)\]\)/m, 1].to_s.scan(/'([^']+)'/).flatten
allow_set = allow.map(&:downcase)
allowed = lambda do |host|
  allow_set.any? { |a| host == a || host.end_with?('.' + a) } || host.end_with?('.gov.tw', '.edu.tw') || %w[gov.tw edu.tw].include?(host)
end

categories = []
cat_index = lambda do |label, source|
  i = categories.index { |c| c['label'] == label && c['source'] == source }
  return i if i
  categories << { 'label' => label, 'source' => source }
  categories.size - 1
end

entries = {} # host => category index（先出現的保留：停止解析資料優先）
skipped_allow = []

puts '下載：遭停止解析涉詐網站…'
sus = CSV.parse(download(SUSPENDED_URL).sub(/\A﻿/, ''), headers: true)
months = []
sus.each do |r|
  host = normalize_host(r['網域'])
  next unless host
  if allowed.call(host)
    skipped_allow << host
    next
  end
  months << r['民國年月']
  entries[host] ||= cat_index.call(sector_label(r['網站性質']), 'suspended')
end

puts '下載：假投資(博弈)網站…'
inv = CSV.parse(download(INVEST_URL).sub(/\A﻿/, ''), headers: true)
inv_dates = []
inv_index = cat_index.call('假投資（博弈）網站', 'invest')
inv.each do |r|
  host = normalize_host(r['網址'])
  next unless host
  if allowed.call(host)
    skipped_allow << host
    next
  end
  inv_dates << r['統計結束日期']
  entries[host] ||= inv_index
end

latest_month = roc_month_to_label(months.compact.max)
meta = {
  'version' => 1,
  'generatedAt' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
  'dataMonth' => latest_month,
  'count' => entries.size,
  'categories' => categories,
  'sources' => {
    'suspended' => {
      'title' => '165反詐騙諮詢專線_遭停止解析涉詐網站',
      'url' => 'https://data.gov.tw/dataset/176455',
      'download' => SUSPENDED_URL,
      'rows' => sus.size,
      'latest' => latest_month,
    },
    'invest' => {
      'title' => '165反詐騙諮詢專線_假投資(博弈)網站',
      'url' => 'https://data.gov.tw/dataset/160055',
      'rows' => inv.size,
      'latest' => inv_dates.compact.max,
    },
  },
  'publisher' => '內政部警政署',
  'license' => '政府資料開放授權條款第1版',
}

File.write(OUT_LIST, entries.sort.map { |h, i| "#{h}\t#{i}" }.join("\n") + "\n")
File.write(OUT_META, JSON.pretty_generate(meta) + "\n")
puts "完成：#{entries.size} 個網域（資料月份 #{latest_month}），略過白名單 #{skipped_allow.uniq.size} 筆 #{skipped_allow.uniq.first(5).inspect}"
puts "  #{OUT_LIST}（#{File.size(OUT_LIST)} bytes）"

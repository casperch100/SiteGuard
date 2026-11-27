# encoding: utf-8
# 產生「正常網域」清單，用來計算誤判率。
#
#   ruby -Ku tools/eval/build_negatives.rb
#
# 來源：Tranco 熱門網站排行（https://tranco-list.eu/）
#   - 全球前 10,000 名
#   - 前 100 萬名中的 .tw 網域前 2,000 名（代表台灣常用網站）
# 輸出：eval/cache/negatives.txt（每行一個網域；不放進 git，每次評估時重新下載）
#       eval/cache/negatives_holdout.txt（保留組：全球第 10,001–30,000 名＋ .tw 第 2,001–4,000 名）
#
# 保留組用來估計「沒看過的網站」的誤判率：調整規則時只看 negatives.txt 的誤判清單，
# 不要看保留組被誤判的網域，否則保留組就失去檢驗的意義。
#
# Tranco 由多個來源組成，部分來源採 CC BY-NC 4.0 與 CC BY-SA 4.0 授權，
# 因此只在評估時下載使用，不重新散布。

require 'fileutils'
require 'set'
require 'time'
require_relative 'common'

ROOT = File.expand_path('../..', __dir__)
CACHE = File.join(ROOT, 'eval/cache')
OUT = File.join(CACHE, 'negatives.txt')
META = File.join(CACHE, 'negatives.meta')
GLOBAL_TOP = 10_000
TW_TOP = 2_000
HOLDOUT = File.join(CACHE, 'negatives_holdout.txt')
HOLDOUT_GLOBAL_TOP = 30_000
HOLDOUT_TW_TOP = 4_000

FileUtils.mkdir_p(CACHE)
zip_path = File.join(CACHE, 'tranco.zip')

# 一週內下載過就重用
if !File.exist?(zip_path) || Time.now - File.mtime(zip_path) > 7 * 86_400
  puts '下載 Tranco 熱門網站排行…'
  data = EvalCommon.http_get_binary('https://tranco-list.eu/top-1m.csv.zip', 'User-Agent' => 'siteguard-eval')
  File.binwrite(zip_path, data)
end

csv = IO.popen(['unzip', '-p', zip_path], &:read)
raise 'Tranco 解壓縮失敗' if csv.to_s.empty?

global = []
tw = []
hold_global = []
hold_tw = []
tw_seen = 0
csv.each_line do |line|
  rank, domain = line.strip.split(',', 2)
  next unless domain
  host = EvalCommon.normalize_host(domain)
  next unless host
  r = rank.to_i
  if r <= GLOBAL_TOP
    global << host
  elsif r <= HOLDOUT_GLOBAL_TOP
    hold_global << host
  end
  if host.end_with?('.tw')
    tw_seen += 1
    if tw_seen <= TW_TOP then tw << host
    elsif tw_seen <= HOLDOUT_TW_TOP then hold_tw << host
    end
  end
  break if r > HOLDOUT_GLOBAL_TOP && tw_seen >= HOLDOUT_TW_TOP
end

all = (global + tw).uniq
File.write(OUT, all.join("\n") + "\n")
holdout = (hold_global + hold_tw).uniq - all
File.write(HOLDOUT, holdout.join("\n") + "\n")
File.write(META, "tranco_downloaded=#{File.mtime(zip_path).utc.strftime('%Y-%m-%d')}\nglobal=#{global.size}\ntw=#{tw.size}\ntotal=#{all.size}\nholdout=#{holdout.size}\n")
puts "完成：全球前 #{global.size} 名 + .tw 前 #{tw.size} 名，共 #{all.size} 個網域 → #{OUT}"
puts "保留組：#{holdout.size} 個網域 → #{HOLDOUT}"

# --- 正常網域的註冊日期（抽樣） ---
# 網域年齡規則也可能誤判「剛成立的正常網站」，所以要抽樣查詢正常網域的註冊日期，
# 誤判率才不會被低估。固定亂數種子，讓每次抽到的樣本一致；30 天內查過就重用。
require 'json'
AGES = File.join(CACHE, 'negatives_age.json')
SAMPLE = (ENV['NEG_AGE_SAMPLE'] || 1000).to_i
cached = File.exist?(AGES) ? JSON.parse(File.read(AGES)) : {}
fresh = cached['checkedAt'] && Time.now - Time.parse(cached['checkedAt']) < 30 * 86_400
if fresh && cached['sample'].to_i >= SAMPLE
  puts "正常網域註冊日期：使用 #{cached['checkedAt'][0, 10]} 的快取（#{cached['ages'].size} 個）"
else
  regs = all.map { |h| EvalCommon.registrable(h) }.reject { |_, platform| platform }.map(&:first).uniq
  sample = regs.sample(SAMPLE, random: Random.new(20_261_127))
  puts "查詢 #{sample.size} 個正常網域的註冊日期…"
  res = EvalCommon.rdap_lookup_many(sample, threads: 6)
  ages = res.select { |_, r| r[0] == 'ok' }.map { |d, r| [d, r[1].to_s] }.to_h
  File.write(AGES, JSON.generate('checkedAt' => Time.now.utc.iso8601, 'sample' => sample.size, 'ages' => ages, 'sampleDomains' => sample))
  st = Hash.new(0)
  res.each_value { |r| st[r[0]] += 1 }
  puts "  完成：#{st.map { |k, v| "#{k}=#{v}" }.join(', ')}"
end

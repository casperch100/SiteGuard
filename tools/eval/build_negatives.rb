# encoding: utf-8
# 產生「正常網域」清單，用來計算誤判率。
#
#   ruby -Ku tools/eval/build_negatives.rb
#
# 來源：Tranco 熱門網站排行（https://tranco-list.eu/）
#   - 全球前 10,000 名
#   - 前 100 萬名中的 .tw 網域前 2,000 名（代表台灣常用網站）
# 輸出：eval/cache/negatives.txt（每行一個網域；不放進 git，每次評估時重新下載）
#
# Tranco 由多個來源組成，部分來源採 CC BY-NC 4.0 與 CC BY-SA 4.0 授權，
# 因此只在評估時下載使用，不重新散布。

require 'fileutils'
require 'set'
require_relative 'common'

ROOT = File.expand_path('../..', __dir__)
CACHE = File.join(ROOT, 'eval/cache')
OUT = File.join(CACHE, 'negatives.txt')
META = File.join(CACHE, 'negatives.meta')
GLOBAL_TOP = 10_000
TW_TOP = 2_000

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
csv.each_line do |line|
  rank, domain = line.strip.split(',', 2)
  next unless domain
  host = EvalCommon.normalize_host(domain)
  next unless host
  global << host if rank.to_i <= GLOBAL_TOP
  tw << host if (host.end_with?('.tw') || host == 'tw') && tw.size < TW_TOP
  break if global.size >= GLOBAL_TOP && tw.size >= TW_TOP
end

all = (global + tw).uniq
File.write(OUT, all.join("\n") + "\n")
File.write(META, "tranco_downloaded=#{File.mtime(zip_path).utc.strftime('%Y-%m-%d')}\nglobal=#{global.size}\ntw=#{tw.size}\ntotal=#{all.size}\n")
puts "完成：全球前 #{global.size} 名 + .tw 前 #{tw.size} 名，共 #{all.size} 個網域 → #{OUT}"

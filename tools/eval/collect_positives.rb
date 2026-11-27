# encoding: utf-8
# 收集「仍在線」的詐騙／釣魚網域，並在收集當下查詢註冊日期（RDAP），累積成評估資料集。
#
#   ruby -Ku tools/eval/collect_positives.rb            # 每天執行
#   ruby -Ku tools/eval/collect_positives.rb --165 download   # 只收 165 最新一個月新增的網域（也可給本機 CSV 路徑）
#   ruby -Ku tools/eval/collect_positives.rb --165 download --phishtank   # 兩者都收
#
# 輸出：eval/data/positives.csv（只附加新網域，不重複）
#   欄位：collected_at, host, registrable, platform, source, target, reported_at, reg_date, rdap_status
#
# 資料來源：
#   - PhishTank（Cisco Talos）已驗證且仍在線的釣魚網址 https://phishtank.org/
#     只保留網域與收集當下的特徵，不保存完整網址。
#   - 165 反詐騙諮詢專線_遭停止解析涉詐網站（選用，--165）
require 'csv'
require 'json'
require 'net/http'
require 'uri'
require 'set'
require 'time'
require_relative 'common'

ROOT = File.expand_path('../..', __dir__)
OUT = File.join(ROOT, 'eval/data/positives.csv')
HEADER = %w[collected_at host registrable platform source target reported_at reg_date rdap_status].freeze
PHISHTANK_URL = ENV['PHISHTANK_URL'] || 'https://data.phishtank.com/data/online-valid.csv' # 可用環境變數覆寫（測試用）
FRESH_HOURS = 72          # 只收最近 72 小時內通報的，確保是「新的」詐騙網站
MAX_RDAP_PER_RUN = 400    # 每次最多查詢的網域數，避免對註冊局造成負擔
LOG = File.join(ROOT, 'eval/data/collect-log.csv') # 每次收集的結果（成功或失敗、筆數），報告會顯示最近幾次
LOG_HEADER = %w[run_at runner source status downloaded fresh new_domains rdap_ok rdap_other note].freeze

existing = Set.new
if File.exist?(OUT)
  CSV.foreach(OUT, headers: true) { |r| existing << r['host'] }
else
  FileUtils.mkdir_p(File.dirname(OUT))
  File.write(OUT, HEADER.join(',') + "\n")
end

now = Time.now.utc
candidates = {} # host => {source:, target:, reported_at:}
runs = {}       # source => {status:, downloaded:, fresh:, note:}

# --- PhishTank ---
# 指定 --165 時預設只收 165（避免同一次執行重複下載 PhishTank；未申請金鑰每天只能下載幾次）。
# 兩者都要收：加上 --phishtank。
RUN_PHISHTANK = !ARGV.include?('--165') || ARGV.include?('--phishtank')
if RUN_PHISHTANK
begin
  csv_text = EvalCommon.http_get(PHISHTANK_URL, 'User-Agent' => 'phishtank/siteguard-eval')
  rows = CSV.parse(csv_text, headers: true)
  # 被擋時常會回傳 HTML 錯誤頁而不是 CSV，所以要檢查欄位
  raise "格式不符（不是 PhishTank CSV，開頭：#{csv_text[0, 60].gsub(/\s+/, ' ')}）" unless rows.headers.include?('submission_time')
  cutoff = now - FRESH_HOURS * 3600
  fresh = 0
  rows.each do |r|
    next unless r['verified'] == 'yes' && r['online'] == 'yes'
    t = (Time.parse(r['submission_time']) rescue nil)
    next unless t && t >= cutoff
    fresh += 1
    host = EvalCommon.normalize_host(r['url'])
    next unless host && !existing.include?(host)
    candidates[host] ||= { source: 'phishtank', target: r['target'].to_s, reported_at: t.utc.iso8601 }
  end
  puts "PhishTank：共 #{rows.size} 筆，最近 #{FRESH_HOURS} 小時的新網域 #{candidates.size} 個"
  runs['phishtank'] = { status: 'ok', downloaded: rows.size, fresh: fresh }
rescue StandardError => e
  warn "PhishTank 下載失敗：#{e.message}"
  runs['phishtank'] = { status: 'failed', downloaded: 0, fresh: 0, note: e.message[0, 120] }
end
end

# --- 165 每月新增（選用） ---
SUSPENDED_165_URL = 'https://opdadm.moi.gov.tw/api/v1/no-auth/resource/api/dataset/29E8E643-88ED-4952-B21E-BD42A3B7108C/resource/01EFB21E-DB91-4EDF-843F-F45923BBFA1D/download'
if (i = ARGV.index('--165'))
 begin
  src = ARGV[i + 1]
  csv165 = src && src != 'download' && File.exist?(src) ? File.read(src, encoding: 'bom|utf-8') : EvalCommon.http_get(SUSPENDED_165_URL).sub(/\A﻿/, '')
  rows = CSV.parse(csv165, headers: true)
  latest = rows.map { |r| r['民國年月'] }.compact.max
  older = Set.new(rows.select { |r| r['民國年月'] < latest }.map { |r| EvalCommon.normalize_host(r['網域']) })
  added = 0
  rows.each do |r|
    next unless r['民國年月'] == latest
    host = EvalCommon.normalize_host(r['網域'])
    next if host.nil? || older.include?(host) || existing.include?(host) || candidates.key?(host)
    candidates[host] = { source: '165', target: r['網站性質'].to_s, reported_at: EvalCommon.roc_month_to_iso(latest) }
    added += 1
  end
  puts "165：#{latest} 新增 #{added} 個網域"
  runs['165'] = { status: 'ok', downloaded: rows.size, fresh: added, note: "資料月份 #{latest}" }
 rescue StandardError => e
  warn "165 下載失敗：#{e.message}"
  runs['165'] = { status: 'failed', downloaded: 0, fresh: 0, note: e.message[0, 120] }
 end
end

# --- 查詢註冊日期（以可註冊網域為單位，同一網域只查一次） ---
by_reg = Hash.new { |h, k| h[k] = [] }
candidates.each_key do |host|
  reg, platform = EvalCommon.registrable(host)
  by_reg[platform ? nil : reg] << host
end
regs = by_reg.keys.compact
if regs.size > MAX_RDAP_PER_RUN
  puts "本次只查詢前 #{MAX_RDAP_PER_RUN} 個網域（共 #{regs.size} 個），其餘下次再查"
  regs = regs.first(MAX_RDAP_PER_RUN)
  keep = Set.new(regs)
  candidates.select! do |host, _|
    reg, platform = EvalCommon.registrable(host)
    platform || keep.include?(reg)
  end
end
rdap = EvalCommon.rdap_lookup_many(regs, threads: 4)

# --- 寫入 ---
stats = Hash.new(0)
CSV.open(OUT, 'a') do |out|
  candidates.each do |host, c|
    reg, platform = EvalCommon.registrable(host)
    status, date = platform ? ['platform', nil] : (rdap[reg] || ['skipped', nil])
    stats[status] += 1
    out << [now.iso8601, host, reg, platform ? 1 : 0, c[:source], c[:target], c[:reported_at], date&.to_s, status]
  end
end
puts "新增 #{candidates.size} 筆：#{stats.map { |k, v| "#{k}=#{v}" }.join(', ')}"

# --- 記錄這次收集的結果（報告會顯示最近幾次，不用登入 GitHub 也能確認有沒有被擋） ---
File.write(LOG, LOG_HEADER.join(',') + "\n") unless File.exist?(LOG)
runner = ENV['GITHUB_ACTIONS'] == 'true' ? 'github-actions' : 'local'
by_source = Hash.new { |h, k| h[k] = Hash.new(0) }
candidates.each do |host, c|
  reg, platform = EvalCommon.registrable(host)
  status = platform ? 'platform' : (rdap[reg] || ['skipped'])[0]
  by_source[c[:source]][status == 'ok' ? :ok : :other] += 1
  by_source[c[:source]][:new] += 1
end
CSV.open(LOG, 'a') do |log|
  runs.each do |source, r|
    b = by_source[source]
    log << [now.iso8601, runner, source, r[:status], r[:downloaded], r[:fresh], b[:new], b[:ok], b[:other], r[:note]]
  end
end

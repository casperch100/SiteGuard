# encoding: utf-8
# 沒有 Node.js 時的本機評估：啟動靜態伺服器，用無頭 Chrome 開啟 eval/run.html，
# 取回結果後寫出 eval/REPORT.md 與 eval/history.csv（和 tools/eval/evaluate.mjs 相同）。
#
#   ruby -Ku tools/eval/run_local.rb [--window 28]
require 'json'
require 'net/http'
require 'socket'
require 'tmpdir'
require 'fileutils'

HISTORY_HEADER = 'date,window_days,positives,detection_rules,danger_rules,negatives,false_positive_rules,detection_with_165,false_positive_aged_sample,detection_rules_live'

ROOT = File.expand_path('../..', __dir__)
require 'cgi'
# Chrome 執行檔：可用 CHROME_PATH 指定；預設依序找 macOS 的位置與 PATH 中的 google-chrome／chromium
CHROME = ENV['CHROME_PATH'] ||
         ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser']
           .find { |c| c.start_with?('/') ? File.exist?(c) : system('command', '-v', c, out: File::NULL, err: File::NULL) } ||
         abort('找不到 Chrome，請用 CHROME_PATH 指定執行檔路徑')
window = (i = ARGV.index('--window')) ? ARGV[i + 1].to_i : 28
port = TCPServer.open('127.0.0.1', 0) { |s| s.addr[1] }

server = Process.spawn('ruby', '-run', '-e', 'httpd', ROOT, '-p', port.to_s, out: File::NULL, err: File::NULL)
profile = Dir.mktmpdir('siteguard-eval-')
begin
  20.times do
    break if (Net::HTTP.get_response(URI("http://127.0.0.1:#{port}/eval/run.html")) rescue nil)
    sleep 0.3
  end
  # 用 --dump-dom 取得頁面執行完的 DOM；結果放在 <pre id="report">
  url = "http://127.0.0.1:#{port}/eval/run.html?window=#{window}"
  dom = IO.popen([CHROME, '--headless=new', '--disable-gpu', "--user-data-dir=#{profile}", '--virtual-time-budget=60000',
                  '--dump-dom', url], err: File::NULL, &:read)
  pre = dom[%r{<pre id="report">(.*?)</pre>}m, 1].to_s
  md = CGI.unescapeHTML(pre)
  raise "評估失敗：#{md[0, 300]}" if md.empty? || md.start_with?('評估中', '評估失敗')

  File.write(File.join(ROOT, 'eval/REPORT.md'), md)

  row = CGI.unescapeHTML(dom[%r{<pre id="history"[^>]*>(.*?)</pre>}m, 1].to_s).strip
  unless row.empty?
    hist = File.join(ROOT, 'eval/history.csv')
    lines = File.exist?(hist) ? File.readlines(hist, chomp: true).reject(&:empty?) : [HISTORY_HEADER]
    lines = [lines.first] + lines.drop(1).reject { |l| l.start_with?(row[0, 10] + ',') } # 同一天重跑就覆蓋
    File.write(hist, (lines + [row]).join("\n") + "\n")
  end
  puts md.lines.first(14).join
ensure
  Process.kill('TERM', server) rescue nil
  Process.wait(server) rescue nil
  FileUtils.rm_rf(profile)
end

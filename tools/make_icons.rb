# 產生 SiteGuard 圖示（藍色盾牌 + 白色勾勾），只用 Ruby 標準函式庫。
# 用法：ruby tools/make_icons.rb icons
require 'zlib'
require 'fileutils'

def shield?(x, y)
  return false if y < 0.0 || y > 1.0 || x < 0.0 || x > 1.0
  return true if y < 0.58
  half = 0.5 * (1.0 - y) / 0.42
  (x - 0.5).abs <= half
end

def seg?(px, py, ax, ay, bx, by, w)
  dx = bx - ax; dy = by - ay
  t = (((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0)
  (px - ax - t * dx)**2 + (py - ay - t * dy)**2 <= w * w
end

def check?(x, y)
  seg?(x, y, 0.27, 0.47, 0.44, 0.64, 0.085) || seg?(x, y, 0.44, 0.64, 0.75, 0.30, 0.085)
end

def chunk(type, data)
  [data.bytesize].pack('N') + type + data + [Zlib.crc32(type + data)].pack('N')
end

def render(size, pad)
  ss = 4
  raw = +''.b
  size.times do |j|
    raw << 0.chr
    size.times do |i|
      s = c = 0
      ss.times do |a|
        ss.times do |b|
          x = ((i + (a + 0.5) / ss) / size - pad) / (1 - 2 * pad)
          y = ((j + (b + 0.5) / ss) / size - pad) / (1 - 2 * pad)
          if shield?(x, y)
            s += 1
            c += 1 if check?(x, y)
          end
        end
      end
      alpha = s.to_f / (ss * ss)
      white = s.zero? ? 0 : c.to_f / s
      r = (26 + (229 * white)).round
      g = (115 + (140 * white)).round
      bl = (232 + (23 * white)).round
      raw << [r, g, bl, (255 * alpha).round].pack('C4')
    end
  end
  "\x89PNG\r\n\x1a\n".b + chunk('IHDR', [size, size, 8, 6, 0, 0, 0].pack('NNC5')) +
    chunk('IDAT', Zlib::Deflate.deflate(raw, 9)) + chunk('IEND', '')
end

out = ARGV[0] || 'icons'
FileUtils.mkdir_p(out)
# Chrome Web Store 規定 128px 圖示四周留 16px 透明邊（圖案 96px）
{ 16 => 0.03, 32 => 0.04, 48 => 0.06, 128 => 0.125 }.each do |size, pad|
  File.binwrite(File.join(out, "icon#{size}.png"), render(size, pad))
end
puts 'icons ok'

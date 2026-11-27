// ============================================================
// 判斷規則用的靜態資料
// 詐騙網站名單來自 165 公開資料，見 src/data/165-blocklist.txt 與 src/lib/blocklist.js
// ============================================================

/** 可信任網站（直接判定安全）。 */
export const ALLOWLIST = new Set([
  'google.com', 'google.com.tw', 'youtube.com', 'gstatic.com', 'googleusercontent.com', 'googleapis.com',
  'facebook.com', 'instagram.com', 'line.me', 'apple.com', 'icloud.com', 'microsoft.com', 'live.com',
  'wikipedia.org', 'github.com', 'yahoo.com', 'yahoo.com.tw', 'paypal.com', 'amazon.com', 'netflix.com',
  'shopee.tw', 'momoshop.com.tw', 'pchome.com.tw', 'books.com.tw', '7-11.com.tw', 'ibon.com.tw',
  'cathaybk.com.tw', 'esunbank.com', 'esunbank.com.tw', 'ctbcbank.com', 'taishinbank.com.tw',
  'cht.com.tw', 'taiwanmobile.com', 'fetc.net.tw', 'asus.com', 'ptt.cc', 'dcard.tw',
]);

/** 政府、學術網域後綴（直接判定安全）。 */
export const TRUSTED_SUFFIXES = ['gov.tw', 'edu.tw'];

/**
 * 常被仿冒的品牌：keywords 出現在網址中但不是官方網域 → 可疑。
 * - official：官方網站（顯示在判斷原因中，也用來比對形近字、拼錯一兩個字）
 * - owned：品牌自己的其他網域（CDN、服務、短網址），只用來排除，不拿來比對相似度
 * - ccTld：品牌在各國都有同名網域（google.de、shopee.co.id），同名＋國家後綴視為官方
 * - brandTld：品牌自己的頂級網域（blog.google、edge.apple）
 * - noFuzzy：這些官方網站不做「只差一兩個字」比對（icloud 和常見字 cloud 太像）
 * - tokenStart：這些關鍵字必須出現在片段開頭（huaweicloud、hicloud 不算 icloud）
 * keywords：長度 6 以上用「包含」比對；較短的必須是用 . 或 - 分隔的完整片段，避免誤判一般字詞。
 */
export const BRANDS = [
  { name: '國泰世華銀行', keywords: ['cathaybk', 'cathaybank'], official: ['cathaybk.com.tw'] },
  { name: '玉山銀行', keywords: ['esunbank', 'esun'], official: ['esunbank.com', 'esunbank.com.tw'] },
  { name: '中國信託', keywords: ['ctbcbank', 'ctbc'], official: ['ctbcbank.com'] },
  { name: '台新銀行', keywords: ['taishinbank', 'taishin'], official: ['taishinbank.com.tw'] },
  { name: '中華郵政', keywords: ['chunghwapost', 'twpost', 'posttw', 'post-tw', 'tw-post'], official: ['post.gov.tw'] },
  { name: '遠通電收 eTag', keywords: ['fetc', 'etag'], official: ['fetc.net.tw'] },
  { name: '蝦皮購物', keywords: ['shopee'], official: ['shopee.tw'], ccTld: true,
    owned: ['shopee.com', 'shopee.io', 'shopeemobile.com', 'shopeepay.tw', 'shopee.com.my', 'shopee.com.br'] },
  { name: 'momo 購物', keywords: ['momoshop', 'momo'], official: ['momoshop.com.tw'], owned: ['momo.com.tw'] },
  { name: 'PChome', keywords: ['pchome'], official: ['pchome.com.tw'], owned: ['pchome.tw', 'pchomebiz.com.tw'] },
  { name: 'LINE', keywords: ['line'], official: ['line.me'], owned: ['line-apps.com', 'line-scdn.net', 'naver.jp'] },
  { name: 'Facebook', keywords: ['facebook'], official: ['facebook.com'], ccTld: true,
    owned: ['facebook.net', 'fbcdn.net', 'fb.com', 'facebook-hardware.com'] },
  { name: 'Apple', keywords: ['apple', 'icloud'], official: ['apple.com', 'icloud.com'], ccTld: true, brandTld: 'apple',
    noFuzzy: ['icloud.com'], tokenStart: ['icloud'],
    owned: ['apple.news', 'apple-dns.net', 'apple-dns.cn', 'cdn-apple.com', 'apple-cloudkit.com', 'apple-mapkit.com',
      'icloud-content.com', 'mzstatic.com', 'apple.com.cn', 'icloud.com.cn'] },
  { name: 'Google', keywords: ['google'], ccTld: true, brandTld: 'google',
    official: ['google.com', 'google.com.tw', 'googleusercontent.com', 'googleapis.com'],
    owned: ['google.org', 'google.dev', 'googlevideo.com', 'googletagmanager.com', 'google-analytics.com', 'googlesyndication.com',
      'googleadservices.com', 'googletagservices.com', 'googleblog.com', 'googlecode.com', 'googledomains.com', 'googlehosted.com',
      'googlemail.com', 'googlepages.com', 'googlesource.com', 'googlezip.net', 'googleapis.cn', 'withgoogle.com',
      'thinkwithgoogle.com', 'googleplex.com', 'googledrive.com'] },
  { name: 'PayPal', keywords: ['paypal'], official: ['paypal.com'], ccTld: true, owned: ['paypal.me', 'paypalobjects.com'] },
  { name: 'Netflix', keywords: ['netflix'], official: ['netflix.com'], ccTld: true, owned: ['netflix.net', 'nflxvideo.net'] },
  { name: 'ASUS', keywords: ['asus'], official: ['asus.com'], ccTld: true },
];

/** 詐騙網站常用的頂級網域（參考 165 資料中最常見的後綴）。 */
export const SUSPICIOUS_TLDS = new Set([
  'top', 'xyz', 'icu', 'buzz', 'cyou', 'shop', 'vip', 'club', 'online', 'site', 'live', 'cc', 'rest', 'monster', 'sbs',
]);

/** 網址中的可疑字詞。 */
export const SUSPICIOUS_WORDS = [
  'login', 'verify', 'secure', 'account', 'update', 'wallet', 'invest', 'profit', 'bonus', 'gift', 'free', 'prize', 'refund', 'pay',
];

export const REPORT_CATEGORIES = ['假投資', '假購物', '釣魚（假冒官方）', '博弈', '假抽獎', '其他詐騙'];

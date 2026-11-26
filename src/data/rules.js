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

/** 常被仿冒的品牌：keywords 出現在網址中但不是官方網域 → 可疑。 */
export const BRANDS = [
  { name: '國泰世華銀行', keywords: ['cathaybk', 'cathay'], official: ['cathaybk.com.tw'] },
  { name: '玉山銀行', keywords: ['esunbank', 'esun'], official: ['esunbank.com', 'esunbank.com.tw'] },
  { name: '中國信託', keywords: ['ctbcbank', 'ctbc'], official: ['ctbcbank.com'] },
  { name: '台新銀行', keywords: ['taishinbank', 'taishin'], official: ['taishinbank.com.tw'] },
  { name: '中華郵政', keywords: ['chunghwapost', 'post'], official: ['post.gov.tw'] },
  { name: '遠通電收 eTag', keywords: ['fetc', 'etag'], official: ['fetc.net.tw'] },
  { name: '蝦皮購物', keywords: ['shopee'], official: ['shopee.tw'] },
  { name: 'momo 購物', keywords: ['momoshop', 'momo'], official: ['momoshop.com.tw'] },
  { name: 'PChome', keywords: ['pchome'], official: ['pchome.com.tw'] },
  { name: 'LINE', keywords: ['line'], official: ['line.me'] },
  { name: 'Facebook', keywords: ['facebook'], official: ['facebook.com'] },
  { name: 'Apple', keywords: ['apple', 'icloud'], official: ['apple.com', 'icloud.com'] },
  { name: 'Google', keywords: ['google'], official: ['google.com', 'google.com.tw', 'googleusercontent.com', 'googleapis.com'] },
  { name: 'PayPal', keywords: ['paypal'], official: ['paypal.com'] },
  { name: 'Netflix', keywords: ['netflix'], official: ['netflix.com'] },
  { name: 'ASUS', keywords: ['asus'], official: ['asus.com'] },
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

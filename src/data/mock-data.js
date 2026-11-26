// ============================================================
// 模擬資料（尚未接上真實資料來源）
// 黑名單與網域年齡皆為虛構範例，正式版應改為：
//   - 165 反詐騙公開資料 / 自有情資，每日下載更新
//   - RDAP 查詢真實網域註冊日期
// ============================================================

/** 已知詐騙網站（模擬）。key 可以是可註冊網域或完整主機名稱。 */
export const BLOCKLIST = {
  'shopee-tw-sale.top': { category: '假購物', source: '模擬 165 資料' },
  'momo-outlet-88.shop': { category: '假購物', source: '模擬 165 資料' },
  'gold-invest-vip.xyz': { category: '假投資', source: '模擬 165 資料' },
  'ai-quant-profit.cc': { category: '假投資', source: '模擬 165 資料' },
  'stock-teacher-line.vip': { category: '假投資', source: '模擬 165 資料' },
  'lucky-casino-tw.club': { category: '博弈', source: '模擬 165 資料' },
  'cathaybk-verify.com': { category: '釣魚（假冒銀行）', source: '模擬使用者回報' },
  'etag-fee-pay.top': { category: '釣魚（假冒繳費通知）', source: '模擬 165 資料' },
  'post-tw-parcel.icu': { category: '釣魚（假冒郵局包裹）', source: '模擬 165 資料' },
  'free-iphone-gift.buzz': { category: '假抽獎', source: '模擬使用者回報' },
};

/**
 * 模擬網域註冊天數（正式版改查 RDAP）。
 * 只能放「目前沒有人註冊」的虛構網域，避免對真實網域提供錯誤資訊
 * （例如 paypa1.com 是真實存在、由品牌保護服務代管的網域，所以不列入）。
 */
export const DOMAIN_AGE_DAYS = {
  'shopee-tw-sale.top': 3,
  'gold-invest-vip.xyz': 12,
  'line-login-secure.com': 6,
  'esunbank-tw.online': 9,
  'new-coffee-shop.com': 15,
};

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

/** 詐騙網站常用的頂級網域。 */
export const SUSPICIOUS_TLDS = new Set([
  'top', 'xyz', 'icu', 'buzz', 'cyou', 'shop', 'vip', 'club', 'online', 'site', 'live', 'cc', 'rest', 'monster', 'sbs',
]);

/** 網址中的可疑字詞。 */
export const SUSPICIOUS_WORDS = [
  'login', 'verify', 'secure', 'account', 'update', 'wallet', 'invest', 'profit', 'bonus', 'gift', 'free', 'prize', 'refund', 'pay',
];

export const REPORT_CATEGORIES = ['假投資', '假購物', '釣魚（假冒官方）', '博弈', '假抽獎', '其他詐騙'];

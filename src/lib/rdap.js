// ============================================================
// 網域註冊日期（RDAP）：組查詢網址、解析回應、計算天數
// 純函式；實際的網路查詢與快取在 background.js
// 只送「可註冊網域」（例如 example.com），不送完整網址或路徑；
// 直接向該頂級網域的註冊局查詢（對照表來自 IANA，內建在 src/data/rdap-bootstrap.json）。
// ============================================================

export const CACHE_DAYS = 30;          // 查到註冊日期：快取 30 天
export const NEGATIVE_CACHE_DAYS = 1;  // 查不到（註冊局錯誤、逾時）：1 天後再試
export const LOOKUP_TIMEOUT_MS = 5000;

/** 回傳查詢網址；該頂級網域不支援 RDAP 時回傳 null */
export function rdapUrl(bootstrap, domain) {
  const tld = String(domain).split('.').pop();
  const base = bootstrap?.tlds?.[tld];
  if (!base) return null;
  return `${base.endsWith('/') ? base : base + '/'}domain/${encodeURIComponent(domain)}`;
}

/** 從 RDAP 回應取出註冊日期（YYYY-MM-DD），沒有就回傳 null */
export function parseRegistrationDate(json) {
  const ev = (json?.events || []).find((e) => e.eventAction === 'registration');
  const d = ev?.eventDate ? String(ev.eventDate).slice(0, 10) : null;
  return d && /^\d{4}-\d{2}-\d{2}$/.test(d) ? d : null;
}

/** 註冊至今的天數 */
export function ageInDays(isoDate, now = Date.now()) {
  if (!isoDate) return null;
  const t = Date.parse(`${isoDate}T00:00:00Z`);
  if (Number.isNaN(t)) return null;
  // 註冊日期在未來（電腦時鐘不準或資料錯誤）：無法判斷，不當成剛註冊
  if (t > now + 86400000) return null;
  return Math.max(0, Math.floor((now - t) / 86400000));
}

/** 快取項目是否還有效 */
export function isFresh(entry, now = Date.now()) {
  if (!entry?.checkedAt) return false;
  const days = entry.regDate ? CACHE_DAYS : NEGATIVE_CACHE_DAYS;
  return now - entry.checkedAt < days * 86400000;
}

// ============================================================
// 網站風險判斷引擎（純函式，可在 Service Worker 與 Node 測試中共用）
// ============================================================
import {
  ALLOWLIST, TRUSTED_SUFFIXES, BRANDS, SUSPICIOUS_TLDS, SUSPICIOUS_WORDS,
} from '../data/rules.js';
import { lookupHost, SOURCE_NAME } from './blocklist.js';

export const LEVELS = {
  safe: { label: '可信任網站', color: '#1e8e3e', badge: '✓' },
  unknown: { label: '未發現明顯風險', color: '#5f6368', badge: '' },
  suspicious: { label: '可疑，請小心', color: '#e37400', badge: '?' },
  danger: { label: '危險網站', color: '#d93025', badge: '!' },
};

const DANGER_SCORE = 70;
const SUSPICIOUS_SCORE = 35;

// 常見的二層公眾後綴（簡化版；正式版改用 Public Suffix List）
const MULTI_PART_SUFFIXES = new Set([
  // 和 tools/eval/common.rb 的 MULTI_PART_SUFFIXES 保持一致
  'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw', 'co.uk', 'co.jp', 'com.cn', 'com.hk', 'com.sg', 'com.au',
  'com.br', 'co.in', 'co.kr',
]);

// 任何人都能申請子網域的共用平台（和 tools/eval/common.rb 的 PLATFORMS 保持一致）。
// 這類網址以「子網域」為單位：回報或放行 scam.github.io 不會影響整個 github.io；
// 網域年齡是平台本身的年齡，沒有參考價值，所以不查詢。
export const PLATFORM_SUFFIXES = [
  'blogspot.com', 'web.app', 'firebaseapp.com', 'vercel.app', 'netlify.app', 'github.io', 'pages.dev', 'workers.dev',
  'weebly.com', 'wixsite.com', 'square.site', 'godaddysites.com', 'webflow.io', 'glitch.me', 'herokuapp.com',
  'azurewebsites.net', 'r2.dev', 'framer.app', 'framer.website', 'canva.site', 'my.canva.site', 'onrender.com',
  'replit.app', 'repl.co', 'wordpress.com', 'mystrikingly.com', 'jimdosite.com', 'ipfs.dweb.link', 'gitbook.io',
  'notion.site', 'webcindario.com', '000webhostapp.com', 'duckdns.org', 'ngrok-free.app', 'ngrok.io',
  'trycloudflare.com', 'surge.sh', 'myshopify.com', 'wcomhost.com', 'sites.google.com', 'docs.google.com', 'forms.gle',
  'storage.googleapis.com', 'firebasestorage.googleapis.com', 's3.amazonaws.com', 'cloudfront.net', 'appspot.com',
  'typedream.app', 'carrd.co', 'webnode.page',
];

/** 解析使用者輸入或導航網址。非 http(s) 回傳 null。 */
export function parseTarget(input) {
  let s = String(input ?? '').trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!host) return null;
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[');
  const { registrable, suffix, platform } = isIp ? { registrable: host, suffix: '' } : splitDomain(host);
  return {
    url: u.href,
    protocol: u.protocol,
    host,
    registrable,
    suffix,
    platform: !!platform,
    isIp,
    hasUserInfo: u.username !== '' || u.password !== '',
    userInfo: safeDecode(u.username),
  };
}

// 網址裡的錯誤百分比編碼（例如 %80）會讓 decodeURIComponent 拋出例外：解不開就保留原字串
function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

export function splitDomain(host) {
  const labels = host.split('.');
  if (labels.length <= 1) return { registrable: host, suffix: '' };
  // 共用平台的子網域：最長的平台後綴優先（例如 my.canva.site 先於 canva.site）
  let platform = '';
  for (const p of PLATFORM_SUFFIXES) {
    if (host.endsWith('.' + p) && p.length > platform.length) platform = p;
  }
  if (platform) {
    const n = platform.split('.').length + 1;
    return { registrable: labels.slice(-n).join('.'), suffix: platform, platform: true };
  }
  const lastTwo = labels.slice(-2).join('.');
  const suffixLen = MULTI_PART_SUFFIXES.has(lastTwo) && labels.length >= 3 ? 2 : 1;
  return {
    registrable: labels.slice(-(suffixLen + 1)).join('.'),
    suffix: labels.slice(-suffixLen).join('.'),
  };
}

/** 去掉公眾後綴後的主要名稱，例如 cathaybk.com.tw → cathaybk */
function coreName(domain) {
  const { registrable, suffix } = splitDomain(domain);
  return suffix ? registrable.slice(0, -(suffix.length + 1)) : registrable;
}

// 常見的形近字替換（0→o、1→l、rn→m …）
function normalizeHomoglyphs(s) {
  return s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/[1!|]/g, 'l')
    .replace(/3/g, 'e').replace(/5/g, 's').replace(/4/g, 'a').replace(/7/g, 't');
}

export function levenshtein(a, b) {
  if (a === b) return 0;
  const dp = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length];
}

function isAllowlisted(t) {
  if (ALLOWLIST.has(t.registrable) || ALLOWLIST.has(t.host)) return true;
  return TRUSTED_SUFFIXES.some((s) => t.host === s || t.host.endsWith('.' + s));
}

function lookupReports(reports, t) {
  return reports[t.host] || reports[t.registrable] || null;
}

/** 供建置腳本與更新程式共用：主機名稱是否在白名單（白名單上的網域不列入 165 名單） */
export function isAllowedHost(host) {
  const t = parseTarget(host);
  return !!t && isAllowlisted(t);
}

/** 找出最像哪個品牌的仿冒網址（只取最強的一條理由）。 */
function brandSignal(t) {
  const tokens = t.host.split(/[.-]/);
  const core = coreName(t.registrable);
  const normCore = normalizeHomoglyphs(core);
  let best = null;
  const consider = (weight, text) => { if (!best || weight > best.weight) best = { weight, text }; };

  for (const brand of BRANDS) {
    if (brand.official.some((d) => t.registrable === d || t.host.endsWith('.' + d))) continue;

    for (const official of brand.official) {
      const oCore = coreName(official);
      if (core === oCore) {
        consider(45, `網域名稱和「${brand.name}」官方網站（${official}）相同，但網域後綴不同`);
      } else if (normCore === oCore) {
        consider(50, `網址「${t.registrable}」用形近字元仿冒「${brand.name}」（${official}）`);
      } else if (oCore.length >= 5) {
        const d = levenshtein(normCore, oCore);
        if (d === 1 || (d === 2 && oCore.length >= 8)) {
          consider(50, `網址「${t.registrable}」和「${brand.name}」官方網站（${official}）只差 ${d} 個字`);
        }
      }
    }

    const hit = brand.keywords.find((k) => (k.length >= 6 ? t.host.includes(k) : tokens.includes(k)));
    if (hit) consider(40, `網址含有「${hit}」字樣，但不是「${brand.name}」的官方網站`);
  }
  return best;
}

/** 網域年齡規則的分數（第 5 步依評估結果調整） */
export const AGE_RULES = [
  { maxDays: 30, weight: 40, text: (d) => `網域註冊僅 ${d} 天` },
  { maxDays: 90, weight: 30, text: (d) => `網域註冊未滿 3 個月（${d} 天）` },
  { maxDays: 180, weight: 15, text: (d) => `網域註冊未滿半年（${d} 天）` },
];

/**
 * 這個網址需不需要查詢網域註冊日期？需要的話回傳要查的可註冊網域，否則回傳 null。
 * 白名單、政府網站、IP 位址、本機網址、165 名單上的網站都不查（不必要，也避免送出多餘的網域）。
 */
export function domainForAgeLookup(input, { reports = {}, blocklist = null } = {}) {
  const t = parseTarget(input);
  if (!t || t.isIp || t.platform || isLocal(t.host) || !t.registrable.includes('.')) return null;
  if (lookupReports(reports, t) || lookupHost(blocklist, t.host, t.registrable) || isAllowlisted(t)) return null;
  return t.registrable;
}

/**
 * 評估一個網址的風險。
 * @param {string} input 網址或網域
 * @param {{reports?: Record<string, {category: string}>, blocklist?: {hosts: Map, meta: object},
 *          domainAgeDays?: (registrable: string) => number|null}} [opts]
 *   reports：使用者本機回報；blocklist：165 涉詐網站名單（見 blocklist.js）；
 *   domainAgeDays：查詢網域註冊天數（查不到或還沒查回傳 null）
 */
export function assessUrl(input, { reports = {}, blocklist = null, domainAgeDays = null } = {}) {
  const t = parseTarget(input);
  if (!t) return { ok: false, input, error: '不是有效的網址' };

  const base = { ok: true, input, url: t.url, host: t.host, registrable: t.registrable, checkedAt: Date.now() };
  const reasons = [];
  const add = (weight, text) => reasons.push({ weight, text });

  // 1. 使用者自己回報過 → 危險
  const reported = lookupReports(reports, t);
  if (reported) {
    return { ...base, level: 'danger', score: 100, category: reported.category, reported: true,
      reasons: [{ weight: 100, text: `你曾回報此網站為「${reported.category}」` }] };
  }

  // 2. 165 涉詐網站名單 → 危險
  const blocked = t.isIp ? null : lookupHost(blocklist, t.host, t.registrable);
  if (blocked) {
    const month = blocked.source === 'suspended' ? blocklist.meta?.dataMonth : null;
    const src = `資料來源：${SOURCE_NAME}${month ? `，${month} 資料` : ''}`;
    return { ...base, level: 'danger', score: 100, category: blocked.category, listed165: true,
      reasons: [{ weight: 100, text: `已列入 165 反詐騙公告名單：${blocked.category}（${src}）` }] };
  }

  // 3. 白名單 → 安全
  if (isAllowlisted(t)) {
    return { ...base, level: 'safe', score: 0, reasons: [{ weight: 0, text: '列在可信任網站名單中' }] };
  }

  // 4. 啟發式規則
  const brand = brandSignal(t);
  if (brand) add(brand.weight, brand.text);

  if (t.host.split('.').some((l) => l.startsWith('xn--'))) add(40, '網址使用國際化字元（Punycode），可能是外觀相似的假網址');
  if (t.isIp) add(30, '直接使用 IP 位址，而不是網域名稱');
  if (t.hasUserInfo) {
    if (/^[\w-]+(\.[\w-]+)+$/.test(t.userInfo)) {
      add(45, `網址用「@」偽裝成「${t.userInfo}」，實際會前往「${t.host}」`);
    } else {
      add(30, '網址含有「@」，實際前往的網站可能和看起來的不同');
    }
  }

  const age = !t.isIp && typeof domainAgeDays === 'function' ? domainAgeDays(t.registrable) : null;
  if (typeof age === 'number') {
    const rule = AGE_RULES.find((r) => age <= r.maxDays);
    if (rule) add(rule.weight, rule.text(age));
  }

  const tld = t.host.split('.').pop();
  if (!t.isIp && SUSPICIOUS_TLDS.has(tld)) add(15, `使用詐騙網站常見的網域後綴「.${tld}」`);

  const words = SUSPICIOUS_WORDS.filter((w) => t.host.includes(w));
  if (words.length) add(Math.min(20, words.length * 10), `網址含有可疑字詞：${words.join('、')}`);

  if ((t.registrable.match(/-/g) || []).length >= 3) add(10, '網域名稱含有大量連字號');
  if (!t.isIp && t.host.split('.').length - t.registrable.split('.').length >= 3) add(10, '子網域層數過多');
  if (t.host.length > 45) add(10, '網址主機名稱過長');
  if (t.protocol === 'http:' && !isLocal(t.host)) add(10, '未使用加密連線（HTTPS）');

  const score = Math.min(100, reasons.reduce((s, r) => s + r.weight, 0));
  const level = score >= DANGER_SCORE ? 'danger' : score >= SUSPICIOUS_SCORE ? 'suspicious' : 'unknown';
  reasons.sort((a, b) => b.weight - a.weight);
  if (!reasons.length) reasons.push({ weight: 0, text: '沒有命中任何風險規則' });
  return { ...base, level, score, reasons, ageDays: typeof age === 'number' ? age : null };
}

function isLocal(host) {
  return host === 'localhost' || host === '127.0.0.1' || host.endsWith('.localhost') || host.endsWith('.test');
}

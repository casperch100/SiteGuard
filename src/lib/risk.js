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

// 常見的二層公眾後綴（簡化版，只涵蓋常見國家；完整做法是改用 Public Suffix List）
const MULTI_PART_SUFFIXES = new Set([
  // 和 tools/eval/common.rb 的 MULTI_PART_SUFFIXES 保持一致
  'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.jp', 'ne.jp',
  'or.jp', 'ac.jp', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'com.hk', 'com.sg', 'com.my', 'co.id', 'co.th', 'com.vn',
  'com.ph', 'com.au', 'net.au', 'org.au', 'co.nz', 'com.br', 'com.mx', 'com.ar', 'com.co', 'com.pe', 'co.in',
  'co.kr', 'co.za', 'com.tr', 'com.sa', 'com.eg', 'com.ng', 'com.pk', 'com.bd', 'co.il', 'com.ua',
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
  'typedream.app', 'carrd.co', 'webnode.page', 'googleusercontent.com', 'drive.google.com', 'script.google.com',
];

// 用「網址路徑」區分使用者的共用服務：主機名稱就是服務本身，誰的內容要看路徑。
// 數字是代表「一個使用者／一份內容」的路徑段數，例如 docs.google.com/forms/d/<id> 是 3 段。
// 這類網址不能沿用服務商的可信任判斷，回報與放行也只針對那一份內容，不會影響整個服務。
export const PATH_PLATFORMS = {
  'sites.google.com': 2, 'docs.google.com': 3, 'drive.google.com': 3, 'script.google.com': 3, 'forms.gle': 1,
  'storage.googleapis.com': 1, 'firebasestorage.googleapis.com': 4, 's3.amazonaws.com': 1,
};

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
  // 以路徑區分使用者的服務：取出代表那一份內容的路徑（例如 sites.google.com/view/xxx）
  let tenant = null;
  if (PATH_PLATFORMS[host]) {
    const segs = u.pathname.split('/').filter(Boolean).slice(0, PATH_PLATFORMS[host]);
    tenant = segs.length ? host + '/' + segs.join('/') : null;
  }
  return {
    url: u.href,
    protocol: u.protocol,
    host,
    registrable,
    suffix,
    platform: !!platform,
    tenant,
    siteKey: tenant || registrable, // 回報與放行的單位
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
  if (PATH_PLATFORMS[host]) return { registrable: host, suffix: host, platform: true };
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
  if (t.platform) return false; // 共用平台上的內容是使用者放的，不繼承服務商的可信任判斷
  if (ALLOWLIST.has(t.registrable) || ALLOWLIST.has(t.host)) return true;
  return TRUSTED_SUFFIXES.some((s) => t.host === s || t.host.endsWith('.' + s));
}

function lookupReports(reports, t) {
  return reports[t.siteKey] || reports[t.host] || (t.tenant ? null : reports[t.registrable]) || null;
}

/** 供建置腳本與更新程式共用：主機名稱是否在白名單（白名單上的網域不列入 165 名單） */
export function isAllowedHost(host) {
  const t = parseTarget(host);
  return !!t && isAllowlisted(t);
}

// ---------- 國際化網域（Punycode） ----------
/** 解碼一個 Punycode 標籤（RFC 3492），例如 xn--pypal-4ve → pаypal。格式錯誤回傳 null。 */
export function decodePunycodeLabel(label) {
  if (!label.startsWith('xn--')) return label;
  const input = label.slice(4);
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const adapt = (delta, numPoints, first) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  const digit = (c) => (c >= 48 && c <= 57 ? c - 22 : c >= 97 && c <= 122 ? c - 97 : c >= 65 && c <= 90 ? c - 65 : base);
  const sep = input.lastIndexOf('-');
  const output = sep > 0 ? [...input.slice(0, sep)].map((c) => c.codePointAt(0)) : [];
  let n = 128, i = 0, bias = 72;
  for (let pos = sep > 0 ? sep + 1 : 0; pos < input.length;) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (pos >= input.length) return null;
      const d = digit(input.charCodeAt(pos++));
      if (d >= base) return null;
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i++, 0, n);
  }
  try { return String.fromCodePoint(...output); } catch { return null; }
}

// 外觀和拉丁字母幾乎一樣的西里爾、希臘字母（只列常被用來仿冒的）
const CONFUSABLES = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd',
  'ԛ': 'q', 'ԝ': 'w', 'ӏ': 'l', 'ο': 'o', 'α': 'a', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'κ': 'k', 'ι': 'i',
};

/**
 * 國際化網域的風險：
 * - 'mixed'：拉丁字母混用希臘、西里爾字母（例如 pаypal 的 а 是西里爾字母）→ 常見的仿冒手法
 * - 'native'：其他國際化網域（泰文、中文、帶重音的拉丁字母）→ 正常，不加分
 * 回傳 { kind, ascii }，ascii 是把相似字元換成拉丁字母後的樣子；不是國際化網域回傳 null。
 */
export function idnInfo(host) {
  const labels = host.split('.');
  if (!labels.some((l) => l.startsWith('xn--'))) return null;
  let mixed = false;
  const ascii = labels.map((l) => {
    const u = decodePunycodeLabel(l);
    if (u === null) { mixed = true; return l; }
    const hasLatin = /[a-z]/i.test(u);
    const mapped = [...u].map((c) => CONFUSABLES[c] ?? c).join('');
    if (hasLatin && /[\u0370-\u052f]/.test(u)) mixed = true;       // 同一段裡拉丁字母混用希臘、西里爾字母（重音字母 å ö 不算）
    if (!hasLatin && /^[\x00-\x7f]+$/.test(mapped) && mapped !== u) mixed = true; // 整段都是相似字元（例如全西里爾的 аррӏе）
    return mapped;
  }).join('.');
  return { kind: mixed ? 'mixed' : 'native', ascii };
}

// 任何人都能註冊、也常被當成通用後綴的國碼網域（.cc 也在詐騙常見後綴中）：品牌同名不代表是官方
const OPEN_CCTLDS = new Set(['cc', 'co', 'me', 'tv', 'io', 'ws', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'to', 'la', 'ly', 'gg', 'vc', 'sh', 'nu', 'su']);

const onDomain = (host, d) => host === d || host.endsWith('.' + d);

/** 這個網址是不是品牌自己的網站（官方、品牌擁有的其他網域、各國同名網域、品牌頂級網域） */
function isBrandOwned(brand, host) {
  if (brand.official.some((d) => onDomain(host, d)) || (brand.owned || []).some((d) => onDomain(host, d))) return true;
  if (brand.brandTld && (host === brand.brandTld || host.endsWith('.' + brand.brandTld))) return true;
  if (brand.ccTld) {
    // 同名＋國家後綴：google.de、google.co.jp、google.com.py、shopee.co.id（可以有子網域）
    const h = host.replace(/^www\./, '');
    return brand.official.some((d) => {
      const m = new RegExp(`(^|\\.)${coreName(d)}\\.((com|co|net|org)\\.)?([a-z]{2})$`).exec(h);
      // 直接接在開放註冊的國碼後面（shopee.cc）不算；google.com.co 這種國家二層網域仍算
      return !!m && !(m[2] === undefined && OPEN_CCTLDS.has(m[4]));
    });
  }
  return false;
}

/** 找出最像哪個品牌的仿冒網址（只取最強的一條理由）。 */
function brandSignal(t) {
  const tokens = t.host.split(/[.-]/);
  const core = coreName(t.registrable);
  const normCore = normalizeHomoglyphs(core);
  let best = null;
  const consider = (weight, text) => { if (!best || weight > best.weight) best = { weight, text }; };

  for (const brand of BRANDS) {
    if (isBrandOwned(brand, t.host)) continue;

    for (const official of brand.official) {
      if ((brand.noFuzzy || []).includes(official)) continue;
      const oCore = coreName(official);
      if (core === oCore) {
        consider(45, `網域名稱和「${brand.name}」官方網站（${official}）相同，但網域後綴不同`);
      } else if (normCore === oCore) {
        consider(50, `網址「${t.registrable}」用形近字元仿冒「${brand.name}」（${official}）`);
      } else if (oCore.length >= 6) {
        const d = levenshtein(normCore, oCore);
        if ((d === 1 && oCore.length >= 6) || (d === 2 && oCore.length >= 8)) {
          consider(50, `網址「${t.registrable}」和「${brand.name}」官方網站（${official}）只差 ${d} 個字`);
        }
      }
    }

    const hit = brand.keywords.find((k) => {
      if ((brand.tokenStart || []).includes(k)) return tokens.some((x) => x.startsWith(k)); // huaweicloud 不算 icloud
      return k.length >= 6 ? t.host.includes(k) : tokens.includes(k);
    });
    if (hit) consider(40, `網址含有「${hit}」字樣，但不是「${brand.name}」的官方網站`);
  }
  return best;
}

/** 剛註冊＋詐騙常見後綴的加分（和年齡 40、後綴 15 相加後剛好達到「危險」門檻 70） */
export const NEW_AND_SUSPICIOUS_TLD = { maxDays: 30, weight: 15 };

/** 網域年齡規則的分數 */
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

  const base = { ok: true, input, url: t.url, host: t.host, registrable: t.registrable, siteKey: t.siteKey, checkedAt: Date.now() };
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
  const idn = idnInfo(t.host);
  let brand = brandSignal(t);
  if (idn?.kind === 'mixed') {
    // 把相似字元換回拉丁字母後再比一次品牌：換完剛好是官方網站 → 幾乎可以確定是仿冒
    const owner = BRANDS.find((b) => isBrandOwned(b, idn.ascii));
    const alt = owner
      ? { weight: 50, text: `網址用外觀相似的字元仿冒「${owner.name}」（看起來像 ${idn.ascii}）` }
      : brandSignal(parseTarget(idn.ascii) || t);
    if (alt && (!brand || alt.weight > brand.weight)) brand = alt;
  }
  if (brand) add(brand.weight, brand.text);

  if (idn?.kind === 'mixed') {
    add(40, '網址混用外觀相似的其他文字（Punycode），可能是假網址');
  }
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
  const suspiciousTld = !t.isIp && SUSPICIOUS_TLDS.has(tld);
  if (suspiciousTld) add(15, `使用詐騙網站常見的網域後綴「.${tld}」`);
  // 兩個獨立的訊號同時出現才升為「危險」：剛註冊（30 天內）＋詐騙常見後綴。
  // 評估中約四分之一的新詐騙網站符合（ROADMAP 第 5 步）；只有其中一項時維持「可疑」，降低誤擋新開正常網站的機會。
  if (suspiciousTld && typeof age === 'number' && age <= NEW_AND_SUSPICIOUS_TLD.maxDays) {
    add(NEW_AND_SUSPICIOUS_TLD.weight, '剛註冊的網域又使用詐騙常見的網域後綴，兩者同時出現的正常網站很少');
  }

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

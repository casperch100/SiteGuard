// ============================================================
// Service Worker：攔截危險網站、更新工具列 badge、右鍵選單、訊息中心
// 注意：MV3 Service Worker 隨時可能被回收，狀態一律放 chrome.storage。
// ============================================================
import { assessUrl, parseTarget, isAllowedHost, domainForAgeLookup, LEVELS } from './lib/risk.js';
import { parseList, serializeList, mergeSuspendedCsv, SUSPENDED_CSV_URL } from './lib/blocklist.js';
import { rdapUrl, parseRegistrationDate, ageInDays, isFresh, LOOKUP_TIMEOUT_MS } from './lib/rdap.js';

const WARNING_PAGE = chrome.runtime.getURL('src/warning/warning.html');
const CHECK_PAGE = chrome.runtime.getURL('src/popup/popup.html');
const UPDATE_ALARM = 'update-165';
const MAX_URLS_PER_BATCH = 500; // content script 每批最多送幾個網址（content.js 的 BATCH_SIZE 要小於等於這個值）
const UPDATE_PERIOD_MINUTES = 7 * 24 * 60; // 每週一次（資料集為每月更新）

// ---------- 儲存 ----------
async function getReports() {
  const { reports = {} } = await chrome.storage.local.get('reports');
  return reports;
}

async function getBypass() {
  const { bypass = [] } = await chrome.storage.session.get('bypass');
  return new Set(bypass);
}

// ---------- 165 涉詐網站名單 ----------
// 優先使用上次自動更新存下的名單；沒有的話使用擴充功能內建的快照。
// Service Worker 被回收後會重新載入，所以用 Promise 快取避免重複解析。
let blocklistPromise = null;

function getBlocklist() {
  blocklistPromise ??= loadBlocklist().catch((err) => {
    console.error('SiteGuard：載入 165 名單失敗', err);
    blocklistPromise = null;
    return null;
  });
  return blocklistPromise;
}

async function loadBundledList() {
  const [text, meta] = await Promise.all([
    fetch(chrome.runtime.getURL('src/data/165-blocklist.txt')).then((r) => r.text()),
    fetch(chrome.runtime.getURL('src/data/165-meta.json')).then((r) => r.json()),
  ]);
  return parseList(text, { ...meta, origin: 'bundled' });
}

async function loadBlocklist() {
  // 先比對資料月份，只解析較新的那一份（Service Worker 每次被喚醒都會重新載入，避免解析兩次）
  const [bundledMeta, { list165 }] = await Promise.all([
    fetch(chrome.runtime.getURL('src/data/165-meta.json')).then((r) => r.json()),
    chrome.storage.local.get('list165'),
  ]);
  // 已儲存的名單比內建快照舊（例如擴充功能更新後內建了較新的資料）就不用
  if (list165?.text && (list165.meta?.dataMonth ?? '') >= (bundledMeta.dataMonth ?? '')) {
    return parseList(list165.text, list165.meta);
  }
  return loadBundledList();
}

/** 從政府資料開放平臺下載最新的「遭停止解析涉詐網站」並合併。不會傳送任何使用者資料。 */
async function updateBlocklist() {
  const res = await fetch(SUSPENDED_CSV_URL, { cache: 'no-store', credentials: 'omit' });
  if (!res.ok) throw new Error(`下載失敗：HTTP ${res.status}`);
  const csv = await res.text();
  const base = (await getBlocklist()) ?? (await loadBundledList());
  const merged = mergeSuspendedCsv(csv, base, isAllowedHost);
  const meta = { ...merged.meta, origin: 'updated' };
  await chrome.storage.local.set({ list165: { text: serializeList(merged.hosts), meta } });
  blocklistPromise = Promise.resolve({ hosts: merged.hosts, meta });
  console.info(`SiteGuard：165 名單已更新，新增 ${merged.added} 筆，共 ${merged.hosts.size} 筆（${meta.dataMonth}）`);
  return meta;
}

function scheduleUpdates() {
  chrome.alarms.get(UPDATE_ALARM, (alarm) => {
    if (!alarm) chrome.alarms.create(UPDATE_ALARM, { delayInMinutes: 1, periodInMinutes: UPDATE_PERIOD_MINUTES });
  });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === UPDATE_ALARM) updateBlocklist().catch((err) => console.warn('SiteGuard：165 名單更新失敗，繼續使用目前名單', err));
});
chrome.runtime.onStartup.addListener(scheduleUpdates);

// ---------- 設定 ----------
const DEFAULT_SETTINGS = { domainAgeLookup: true }; // 預設開啟網域年齡查詢（ROADMAP 決定 3）

async function getSettings() {
  const { settings = {} } = await chrome.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...settings };
}

// ---------- 網域年齡（RDAP） ----------
// 只送可註冊網域（例如 example.com），直接查該頂級網域的註冊局；結果快取 30 天（查不到的 1 天後重試）。
const AGE_CACHE_MAX = 3000;
let ageCachePromise = null;
let ageCacheGeneration = 0; // 清除快取時遞增，讓清除前開始的查詢不會把舊資料寫回去
let bootstrapPromise = null;
const inflight = new Map();

function getAgeCache() {
  ageCachePromise ??= chrome.storage.local.get('domainAges').then(async (o) => {
    const cache = o.domainAges || {};
    if (pruneAgeCache(cache)) await chrome.storage.local.set({ domainAges: cache });
    return cache;
  });
  return ageCachePromise;
}

/** 刪除過期的查詢結果（有註冊日期的 30 天、查不到的 1 天），回傳是否有刪除 */
function pruneAgeCache(cache) {
  let removed = false;
  for (const k of Object.keys(cache)) {
    if (!isFresh(cache[k])) {
      delete cache[k];
      removed = true;
    }
  }
  return removed;
}

// 查詢時間只記到日期（UTC），不保存精確的造訪時刻
const today = () => Math.floor(Date.now() / 86400000) * 86400000;

function getBootstrap() {
  bootstrapPromise ??= fetch(chrome.runtime.getURL('src/data/rdap-bootstrap.json')).then((r) => r.json());
  return bootstrapPromise;
}

async function saveAgeCache(cache) {
  pruneAgeCache(cache);
  const keys = Object.keys(cache);
  if (keys.length > AGE_CACHE_MAX) {
    keys.sort((a, b) => cache[a].checkedAt - cache[b].checkedAt)
      .slice(0, keys.length - AGE_CACHE_MAX).forEach((k) => delete cache[k]);
  }
  await chrome.storage.local.set({ domainAges: cache });
}

async function fetchRegistration(domain) {
  const url = rdapUrl(await getBootstrap(), domain);
  if (!url) return { regDate: null, status: 'no_rdap' };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), LOOKUP_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      credentials: 'omit', referrerPolicy: 'no-referrer', signal: ctrl.signal,
      headers: { Accept: 'application/rdap+json, application/json' },
    });
    if (res.status === 404) return { regDate: null, status: 'not_found' };
    if (!res.ok) return { regDate: null, status: `http_${res.status}` };
    const regDate = parseRegistrationDate(await res.json());
    return { regDate, status: regDate ? 'ok' : 'no_date' };
  } catch (err) {
    return { regDate: null, status: err.name === 'AbortError' ? 'timeout' : 'error' };
  } finally {
    clearTimeout(timer);
  }
}

/** 查詢網域註冊日期（同一網域同時只查一次；有快取就不查） */
async function lookupDomainAge(domain) {
  const cache = await getAgeCache();
  if (isFresh(cache[domain])) return cache[domain];
  if (inflight.has(domain)) return inflight.get(domain);
  const generation = ageCacheGeneration;
  const p = fetchRegistration(domain).then(async (r) => {
    const entry = { ...r, checkedAt: today() };
    if (generation !== ageCacheGeneration) return entry; // 查詢期間使用者清除了快取：結果不存
    const latest = await getAgeCache();
    latest[domain] = entry;
    await saveAgeCache(latest);
    return entry;
  }).finally(() => inflight.delete(domain));
  inflight.set(domain, p);
  return p;
}

/**
 * 判斷網址的風險。
 * lookup=true 時，如果需要且還沒查過，會先查詢網域註冊日期（使用者主動查詢、導航時使用）；
 * lookup=false 不對外查詢，只用已快取的結果（工具列 badge、導航時的第一次判斷）。
 * useAgeCache=false 連快取也不用：網頁送來的查詢（連結標記、滑過提示）結果會出現在網頁上，
 * 如果用了個人快取，網頁就能從標記推測使用者查過哪些網域。
 */
async function check(url, { lookup = false, useAgeCache = true } = {}) {
  const [reports, blocklist, settings] = await Promise.all([getReports(), getBlocklist(), getSettings()]);
  const ctx = { reports, blocklist };
  const domain = settings.domainAgeLookup ? domainForAgeLookup(url, ctx) : null;
  const looked = domain && lookup ? await lookupDomainAge(domain) : null;
  const cache = useAgeCache ? await getAgeCache() : {};
  const entry = domain ? (isFresh(cache[domain]) ? cache[domain] : looked) : null;
  const domainAgeDays = (reg) => {
    const e = reg === domain && entry ? entry : cache[reg];
    return e?.regDate ? ageInDays(e.regDate) : null;
  };
  const result = assessUrl(url, { ...ctx, domainAgeDays: settings.domainAgeLookup ? domainAgeDays : null });
  if (result.ok) result.ageLookup = !domain ? 'skipped' : entry ? entry.status : 'pending';
  return result;
}


/**
 * 網頁連結的快取鍵：主機名稱以外，也包含會影響分數的協定與「@」前面的帳號欄位
 * （https://neutral.example/ 和 https://www.bank.com@neutral.example/ 分數不同）。必須和 content.js 的 linkKey 相同。
 */
function linkKey(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.username ? u.username + '@' : ''}${u.hostname.toLowerCase()}`;
  } catch {
    return null;
  }
}

// ---------- 導航攔截 ----------
const navSeq = new Map(); // tabId → 最新一次導航的編號

async function redirectToWarning(tabId, url, result) {
  const bypass = await getBypass();
  if (bypass.has(result.siteKey)) return false;
  await chrome.tabs.update(tabId, { url: `${WARNING_PAGE}?url=${encodeURIComponent(url)}` }).catch(() => {});
  return true;
}

// 注意：onBeforeNavigate 不會暫停導航，請求可能已經送出；這裡做的是「盡快切換到警告頁」，
// 不是在連線前攔截（連線前攔截的設計見 docs/DNR-DESIGN.md，目前暫緩）。
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const seq = (navSeq.get(details.tabId) || 0) + 1;
  navSeq.set(details.tabId, seq);
  const superseded = () => navSeq.get(details.tabId) !== seq; // 判斷期間分頁又開始了新的導航
  const result = await check(details.url);
  if (!result.ok || superseded()) return;
  if (result.level === 'danger') {
    await redirectToWarning(details.tabId, details.url, result);
    return;
  }
  // 還沒查過這個網域的註冊日期：先放行，背景查詢；查到有問題再補上警告
  if (result.ageLookup !== 'pending') return;
  const later = await check(details.url, { lookup: true });
  if (superseded()) return;
  const tab = await chrome.tabs.get(details.tabId).catch(() => null);
  if (!tab) return;
  const current = parseTarget(tab.pendingUrl || tab.url);
  const stillThere = current && current.registrable === later.registrable;
  if (later.level === 'danger' && stillThere) {
    await redirectToWarning(details.tabId, details.url, later);
  } else if (stillThere) {
    updateBadge(details.tabId, tab.pendingUrl || tab.url).catch(() => {});
  }
});

// ---------- 工具列 badge ----------
async function updateBadge(tabId, url) {
  let level = 'unknown';
  if (url?.startsWith(WARNING_PAGE)) {
    level = 'danger';
  } else {
    const result = await check(url);
    if (result.ok) level = result.level;
    else {
      await chrome.action.setBadgeText({ tabId, text: '' });
      return;
    }
  }
  const info = LEVELS[level];
  await chrome.action.setBadgeText({ tabId, text: info.badge });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: info.color });
  await chrome.action.setTitle({ tabId, title: `SiteGuard：${info.label}` });
}

chrome.tabs.onRemoved.addListener((tabId) => navSeq.delete(tabId));

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === 'complete') updateBadge(tabId, tab.url).catch(() => {});
});

// ---------- 右鍵選單 ----------
chrome.runtime.onInstalled.addListener(() => {
  // 更新擴充功能時舊的選單可能還在：先全部移除再建立，避免「重複 id」錯誤
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'check-link', title: '用 SiteGuard 檢查這個連結', contexts: ['link'] });
    chrome.contextMenus.create({ id: 'check-selection', title: '用 SiteGuard 檢查「%s」', contexts: ['selection'] });
  });
  scheduleUpdates();
});

chrome.contextMenus.onClicked.addListener((info) => {
  const target = info.menuItemId === 'check-link' ? info.linkUrl : info.selectionText;
  if (!target) return;
  chrome.windows.create({
    url: `${CHECK_PAGE}?url=${encodeURIComponent(target.trim())}&standalone=1`,
    type: 'popup',
    width: 400,
    height: 600,
  });
});

// ---------- 訊息 ----------
const handlers = {
  // Popup、警告頁傳 lookup: true（使用者主動查看，可以查詢註冊日期）；網頁上的滑過提示不傳（只用快取）
  async check({ url, lookup, fromPage }) {
    return check(url, { lookup: !!lookup && !fromPage, useAgeCache: !fromPage });
  },

  async getSettings() {
    return getSettings();
  },

  async setSettings({ settings }) {
    const next = { ...(await getSettings()), ...settings };
    await chrome.storage.local.set({ settings: next });
    return next;
  },

  // 設定頁的「清除資料」
  async clearData({ what }) {
    if (what === 'reports') await chrome.storage.local.remove('reports');
    if (what === 'domainAges') {
      ageCacheGeneration++;
      ageCachePromise = null;
      await chrome.storage.local.remove('domainAges');
    }
    return { ok: true };
  },

  async stats() {
    const [{ reports = {} }, cache] = await Promise.all([chrome.storage.local.get('reports'), getAgeCache()]);
    return { reports: Object.keys(reports).length, domainAges: Object.keys(cache).length };
  },

  // Popup 顯示 165 資料的版本資訊
  async listInfo() {
    const list = await getBlocklist();
    if (!list) return { ok: false };
    const { dataMonth, count, origin, updatedAt } = list.meta;
    return { ok: true, dataMonth, count: list.hosts.size ?? count, origin, updatedAt };
  },

  // content script 一次送多個網址，回傳以 linkKey 為 key 的結果。
  // 不使用網域年齡（連快取也不用），理由見 check() 的說明。
  async checkMany({ urls }) {
    const [reports, blocklist] = await Promise.all([getReports(), getBlocklist()]);
    const out = {};
    for (const url of (Array.isArray(urls) ? urls : []).slice(0, MAX_URLS_PER_BATCH)) {
      const r = assessUrl(url, { reports, blocklist });
      const key = linkKey(url);
      if (r.ok && key) out[key] = { level: r.level, score: r.score, reasons: r.reasons.slice(0, 3), category: r.category };
    }
    return out;
  },

  async report({ url, category }) {
    const t = parseTarget(url);
    if (!t) return { ok: false };
    const reports = await getReports();
    reports[t.siteKey] = { category, reportedAt: Date.now() };
    await chrome.storage.local.set({ reports });
    return { ok: true };
  },

  async unreport({ url }) {
    const t = parseTarget(url);
    if (!t) return { ok: false };
    const reports = await getReports();
    delete reports[t.siteKey];
    delete reports[t.host];
    if (!t.tenant) delete reports[t.registrable];
    await chrome.storage.local.set({ reports });
    return { ok: true };
  },

  // 使用者在警告頁選擇「仍要前往」：本次瀏覽工作階段內放行此網域
  async bypass({ url }) {
    const t = parseTarget(url);
    if (!t) return { ok: false };
    const bypass = await getBypass();
    bypass.add(t.siteKey);
    await chrome.storage.session.set({ bypass: [...bypass] });
    return { ok: true };
  },
};

// 網頁上的 content script 只需要查詢（而且只用快取）；放行、回報、改設定、清除資料只接受擴充功能自己的頁面
const CONTENT_SCRIPT_TYPES = new Set(['check', 'checkMany']);
const EXTENSION_ORIGIN = chrome.runtime.getURL('');

// 會修改儲存資料的操作依序執行，避免兩個視窗同時回報時，後寫入的覆蓋掉先寫入的
const WRITE_TYPES = new Set(['report', 'unreport', 'bypass', 'setSettings', 'clearData']);
let writeQueue = Promise.resolve();

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const handler = handlers[msg?.type];
  if (!handler || sender.id !== chrome.runtime.id) return false;
  const fromExtensionPage = (sender.url || '').startsWith(EXTENSION_ORIGIN);
  if (!fromExtensionPage) {
    if (!CONTENT_SCRIPT_TYPES.has(msg.type)) {
      sendResponse({ ok: false, error: 'not allowed' });
      return false;
    }
    msg = { ...msg, lookup: false, fromPage: true }; // 網頁不能觸發網域年齡查詢，也不使用個人快取
  }
  const run = WRITE_TYPES.has(msg.type)
    ? (writeQueue = writeQueue.catch(() => {}).then(() => handler(msg)))
    : handler(msg);
  run.then(sendResponse, (err) => sendResponse({ ok: false, error: String(err) }));
  return true; // 非同步回應
});

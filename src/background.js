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
  const bundled = await loadBundledList();
  const { list165 } = await chrome.storage.local.get('list165');
  // 已儲存的名單比內建快照舊（例如擴充功能更新後內建了較新的資料）就不用
  if (list165?.text && (list165.meta?.dataMonth ?? '') >= (bundled.meta.dataMonth ?? '')) {
    return parseList(list165.text, list165.meta);
  }
  return bundled;
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
  ageCachePromise ??= chrome.storage.local.get('domainAges').then((o) => o.domainAges || {});
  return ageCachePromise;
}

function getBootstrap() {
  bootstrapPromise ??= fetch(chrome.runtime.getURL('src/data/rdap-bootstrap.json')).then((r) => r.json());
  return bootstrapPromise;
}

async function saveAgeCache(cache) {
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
    const entry = { ...r, checkedAt: Date.now() };
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
 * lookup=false 只用已快取的結果（網頁連結標記、滑過提示，避免把頁面上每個連結的網域都送出去）。
 */
async function check(url, { lookup = false } = {}) {
  const [reports, blocklist, settings] = await Promise.all([getReports(), getBlocklist(), getSettings()]);
  const ctx = { reports, blocklist };
  const domain = settings.domainAgeLookup ? domainForAgeLookup(url, ctx) : null;
  const looked = domain && lookup ? await lookupDomainAge(domain) : null;
  const cache = await getAgeCache();
  const entry = domain ? (isFresh(cache[domain]) ? cache[domain] : looked) : null;
  const domainAgeDays = (reg) => {
    const e = reg === domain && entry ? entry : cache[reg];
    return e?.regDate ? ageInDays(e.regDate) : null;
  };
  const result = assessUrl(url, { ...ctx, domainAgeDays: settings.domainAgeLookup ? domainAgeDays : null });
  if (result.ok) result.ageLookup = !domain ? 'skipped' : entry ? entry.status : 'pending';
  return result;
}

/** 只用已快取的網域年齡（不對外查詢），給網頁連結的批次標記使用 */
async function cachedAgeFn() {
  const [settings, cache] = await Promise.all([getSettings(), getAgeCache()]);
  if (!settings.domainAgeLookup) return null;
  return (reg) => {
    const e = cache[reg];
    return isFresh(e) && e.regDate ? ageInDays(e.regDate) : null;
  };
}

// ---------- 導航攔截 ----------
async function redirectToWarning(tabId, url, result) {
  const bypass = await getBypass();
  if (bypass.has(result.registrable)) return false;
  await chrome.tabs.update(tabId, { url: `${WARNING_PAGE}?url=${encodeURIComponent(url)}` }).catch(() => {});
  return true;
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const result = await check(details.url);
  if (!result.ok) return;
  if (result.level === 'danger') {
    await redirectToWarning(details.tabId, details.url, result);
    return;
  }
  // 還沒查過這個網域的註冊日期：先放行，背景查詢；查到有問題再補上警告
  if (result.ageLookup !== 'pending') return;
  const later = await check(details.url, { lookup: true });
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

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === 'complete') updateBadge(tabId, tab.url).catch(() => {});
});

// ---------- 右鍵選單 ----------
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: 'check-link', title: '用 SiteGuard 檢查這個連結', contexts: ['link'] });
  chrome.contextMenus.create({ id: 'check-selection', title: '用 SiteGuard 檢查「%s」', contexts: ['selection'] });
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
  async check({ url, lookup }) {
    return check(url, { lookup: !!lookup });
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

  // content script 一次送多個網址，回傳以 host 為 key 的結果
  async checkMany({ urls }) {
    const [reports, blocklist, domainAgeDays] = await Promise.all([getReports(), getBlocklist(), cachedAgeFn()]);
    const out = {};
    for (const url of urls.slice(0, MAX_URLS_PER_BATCH)) {
      const r = assessUrl(url, { reports, blocklist, domainAgeDays });
      if (r.ok) out[r.host] = { level: r.level, score: r.score, reasons: r.reasons.slice(0, 3), category: r.category };
    }
    return out;
  },

  async report({ url, category }) {
    const t = parseTarget(url);
    if (!t) return { ok: false };
    const reports = await getReports();
    reports[t.registrable] = { category, reportedAt: Date.now() };
    await chrome.storage.local.set({ reports });
    return { ok: true };
  },

  async unreport({ url }) {
    const t = parseTarget(url);
    if (!t) return { ok: false };
    const reports = await getReports();
    delete reports[t.registrable];
    delete reports[t.host];
    await chrome.storage.local.set({ reports });
    return { ok: true };
  },

  // 使用者在警告頁選擇「仍要前往」：本次瀏覽工作階段內放行此網域
  async bypass({ url }) {
    const t = parseTarget(url);
    if (!t) return { ok: false };
    const bypass = await getBypass();
    bypass.add(t.registrable);
    await chrome.storage.session.set({ bypass: [...bypass] });
    return { ok: true };
  },
};

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const handler = handlers[msg?.type];
  if (!handler) return false;
  handler(msg).then(sendResponse, (err) => sendResponse({ ok: false, error: String(err) }));
  return true; // 非同步回應
});

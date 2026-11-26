// ============================================================
// Service Worker：攔截危險網站、更新工具列 badge、右鍵選單、訊息中心
// 注意：MV3 Service Worker 隨時可能被回收，狀態一律放 chrome.storage。
// ============================================================
import { assessUrl, parseTarget, isAllowedHost, LEVELS } from './lib/risk.js';
import { parseList, serializeList, mergeSuspendedCsv, SUSPENDED_CSV_URL } from './lib/blocklist.js';

const WARNING_PAGE = chrome.runtime.getURL('src/warning/warning.html');
const CHECK_PAGE = chrome.runtime.getURL('src/popup/popup.html');
const UPDATE_ALARM = 'update-165';
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

async function check(url) {
  const [reports, blocklist] = await Promise.all([getReports(), getBlocklist()]);
  return assessUrl(url, { reports, blocklist });
}

// ---------- 導航攔截 ----------
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const result = await check(details.url);
  if (!result.ok || result.level !== 'danger') return;

  const bypass = await getBypass();
  if (bypass.has(result.registrable)) return;

  const target = `${WARNING_PAGE}?url=${encodeURIComponent(details.url)}`;
  chrome.tabs.update(details.tabId, { url: target }).catch(() => {});
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
  async check({ url }) {
    return check(url);
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
    const [reports, blocklist] = await Promise.all([getReports(), getBlocklist()]);
    const out = {};
    for (const url of urls.slice(0, 500)) {
      const r = assessUrl(url, { reports, blocklist });
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

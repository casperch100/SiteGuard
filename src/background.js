// ============================================================
// Service Worker：攔截危險網站、更新工具列 badge、右鍵選單、訊息中心
// 注意：MV3 Service Worker 隨時可能被回收，狀態一律放 chrome.storage。
// ============================================================
import { assessUrl, parseTarget, LEVELS } from './lib/risk.js';

const WARNING_PAGE = chrome.runtime.getURL('src/warning/warning.html');
const CHECK_PAGE = chrome.runtime.getURL('src/popup/popup.html');

// ---------- 儲存 ----------
async function getReports() {
  const { reports = {} } = await chrome.storage.local.get('reports');
  return reports;
}

async function getBypass() {
  const { bypass = [] } = await chrome.storage.session.get('bypass');
  return new Set(bypass);
}

async function check(url) {
  return assessUrl(url, { reports: await getReports() });
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

  // content script 一次送多個網址，回傳以 host 為 key 的結果
  async checkMany({ urls }) {
    const reports = await getReports();
    const out = {};
    for (const url of urls.slice(0, 500)) {
      const r = assessUrl(url, { reports });
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

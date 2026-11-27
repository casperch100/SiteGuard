// ============================================================
// Content Script：標記頁面上的危險／可疑連結，滑鼠移上去顯示風險 Tooltip
// （content script 無法 import ES module，判斷一律交給 Service Worker）
// ============================================================
(() => {
  if (window.__siteGuardLoaded) return;
  window.__siteGuardLoaded = true;

  const LEVEL_TEXT = {
    safe: ['可信任網站', '#1e8e3e'],
    unknown: ['未發現明顯風險', '#5f6368'],
    suspicious: ['可疑網站，請小心', '#e37400'],
    danger: ['危險網站', '#d93025'],
  };
  const MAX_LINKS_PER_SCAN = 2000;
  const BATCH_SIZE = 200; // 每次送給背景的網址數，要小於等於 background.js 的 MAX_URLS_PER_BATCH
  const cache = new Map(); // linkKey -> result
  const pending = new Set();

  const send = (msg) => chrome.runtime.sendMessage(msg).catch(() => null);

  /**
   * 連結的主機名稱與快取鍵。快取鍵包含協定與「@」前面的帳號欄位，因為它們會影響分數
   * （https://www.bank.com@neutral.example/ 不能沿用 https://neutral.example/ 的結果）。
   * 必須和 background.js 的 linkKey 相同。
   */
  function linkInfo(a) {
    try {
      const u = new URL(a.href, location.href);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
      const host = u.hostname.toLowerCase();
      return { host, key: `${u.protocol}//${u.username ? u.username + '@' : ''}${host}` };
    } catch { return null; }
  }

  function applyMark(a, result) {
    a.dataset.sgDone = '1';
    if (result && (result.level === 'danger' || result.level === 'suspicious')) {
      a.dataset.sgLevel = result.level;
    } else {
      delete a.dataset.sgLevel;
    }
  }

  // ---------- 掃描頁面上的連結 ----------
  async function scan() {
    const anchors = [...document.querySelectorAll('a[href]:not([data-sg-done])')].slice(0, MAX_LINKS_PER_SCAN);
    const toCheck = new Map(); // linkKey -> sample url
    for (const a of anchors) {
      const info = linkInfo(a);
      if (!info || info.host === location.hostname) { a.dataset.sgDone = '1'; continue; }
      if (cache.has(info.key)) applyMark(a, cache.get(info.key));
      else if (!pending.has(info.key)) toCheck.set(info.key, a.href);
    }
    if (!toCheck.size) return;

    toCheck.forEach((_, h) => pending.add(h));
    const urls = [...toCheck.values()];
    const results = {};
    for (let i = 0; i < urls.length; i += BATCH_SIZE) {
      Object.assign(results, (await send({ type: 'checkMany', urls: urls.slice(i, i + BATCH_SIZE) })) || {});
    }
    for (const key of toCheck.keys()) {
      cache.set(key, results[key] || null);
      pending.delete(key);
    }
    for (const a of anchors) {
      const info = linkInfo(a);
      if (info && cache.has(info.key)) applyMark(a, cache.get(info.key));
    }
    // 查詢期間新出現、而且網域剛好在查詢中的連結，這一輪沒有被標記；再掃一次（只會用快取，不會重複查詢）
    if (document.querySelector('a[href]:not([data-sg-done])')) scheduleScan();
  }

  let scanTimer = null;
  const scheduleScan = () => {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scan, 400);
  };
  new MutationObserver(scheduleScan).observe(document.documentElement, { childList: true, subtree: true });
  scan();

  // ---------- Tooltip（Shadow DOM，避免和網站 CSS 互相影響） ----------
  const tipHost = document.createElement('div');
  tipHost.style.cssText = 'position:fixed;top:0;left:0;z-index:2147483647;pointer-events:none;';
  const root = tipHost.attachShadow({ mode: 'closed' });
  root.innerHTML = `
    <style>
      .tip { position: fixed; max-width: 320px; padding: 10px 12px; border-radius: 10px;
        background: #202124; color: #e8eaed; box-shadow: 0 4px 16px rgba(0,0,0,.3);
        font: 13px/1.5 system-ui, -apple-system, "PingFang TC", "Noto Sans TC", "Microsoft JhengHei", sans-serif;
        opacity: 0; transition: opacity .12s; }
      .tip.show { opacity: 1; }
      .head { display: flex; align-items: center; gap: 6px; font-weight: 700; }
      .dot { width: 9px; height: 9px; border-radius: 50%; flex: none; }
      .host { color: #9aa0a6; font: 12px ui-monospace, Menlo, monospace; word-break: break-all; margin: 2px 0 4px; }
      ul { margin: 0; padding-left: 16px; }
      .brand { margin-top: 6px; color: #9aa0a6; font-size: 11px; }
    </style>
    <div class="tip" role="tooltip"></div>`;
  const tip = root.querySelector('.tip');
  let tipAttached = false;
  let hoverTimer = null;
  let hoverAnchor = null;

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function renderTip(a, host, result) {
    if (!tipAttached) { document.documentElement.appendChild(tipHost); tipAttached = true; }
    const [label, color] = LEVEL_TEXT[result?.level] || ['無法判斷', '#5f6368'];
    const reasons = (result?.reasons || []).filter((r) => r.weight > 0).slice(0, 3);
    tip.innerHTML = `
      <div class="head"><span class="dot" style="background:${color}"></span><span style="color:${color === '#5f6368' ? '#e8eaed' : color}">${label}</span></div>
      <div class="host">${esc(host)}</div>
      ${reasons.length ? `<ul>${reasons.map((r) => `<li>${esc(r.text)}</li>`).join('')}</ul>` : ''}
      <div class="brand">SiteGuard 網站安全檢查</div>`;

    const rect = a.getBoundingClientRect();
    tip.style.left = '0px';
    tip.style.top = '0px';
    const w = tip.offsetWidth;
    const h = tip.offsetHeight;
    const left = Math.min(Math.max(8, rect.left), window.innerWidth - w - 8);
    const top = rect.bottom + 8 + h < window.innerHeight ? rect.bottom + 8 : Math.max(8, rect.top - h - 8);
    tip.style.left = `${left}px`;
    tip.style.top = `${top}px`;
    tip.classList.add('show');
  }

  function hideTip() {
    clearTimeout(hoverTimer);
    hoverAnchor = null;
    tip.classList.remove('show');
  }

  document.addEventListener('mouseover', (e) => {
    const a = e.target.closest?.('a[href]');
    if (!a || a === hoverAnchor) return;
    const info = linkInfo(a);
    if (!info || info.host === location.hostname) return;
    const host = info.host;
    hideTip();
    hoverAnchor = a;
    hoverTimer = setTimeout(async () => {
      let result = cache.get(info.key);
      if (result === undefined) {
        result = await send({ type: 'check', url: a.href });
        if (result?.ok) cache.set(info.key, result);
      }
      if (hoverAnchor === a) renderTip(a, host, result);
    }, 300);
  }, true);

  document.addEventListener('mouseout', (e) => {
    if (hoverAnchor && !hoverAnchor.contains(e.relatedTarget)) hideTip();
  }, true);
  window.addEventListener('scroll', hideTip, { passive: true, capture: true });
})();

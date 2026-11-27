import { LEVELS } from '../lib/risk.js';
import { REPORT_CATEGORIES } from '../data/rules.js';

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const WARNING_PAGE = chrome.runtime.getURL('src/warning/warning.html');

let currentUrl = '';

if (params.get('standalone')) document.body.classList.add('standalone');

for (const c of REPORT_CATEGORIES) $('report-category').add(new Option(c, c));

async function resolveInitialUrl() {
  if (params.get('url')) return params.get('url');
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || '';
  // 在警告頁上開 popup 時，顯示被擋下的原始網址
  if (url.startsWith(WARNING_PAGE)) return new URL(url).searchParams.get('url') || '';
  return url;
}

async function show(url) {
  currentUrl = url;
  const result = await chrome.runtime.sendMessage({ type: 'check', url, lookup: true });
  const box = $('result');

  if (!result?.ok) {
    box.dataset.level = 'invalid';
    $('label').textContent = '無法檢查此頁面';
    $('host').textContent = url ? url.slice(0, 80) : '';
    $('score').textContent = '';
    $('category').hidden = true;
    $('reasons').replaceChildren();
    $('report-section').hidden = true;
    return;
  }

  box.dataset.level = result.level;
  $('label').textContent = LEVELS[result.level].label;
  $('host').textContent = result.host;
  $('score').textContent = result.level === 'safe' ? '' : result.score;
  $('category').hidden = !result.category;
  $('category').textContent = result.category || '';
  $('reasons').replaceChildren(...result.reasons.map((r) => {
    const li = document.createElement('li');
    li.textContent = r.text;
    return li;
  }));

  $('report-section').hidden = result.level === 'safe';
  $('report-form').hidden = !!result.reported;
  $('reported').hidden = !result.reported;
}

$('check-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const v = $('check-input').value.trim();
  if (v) show(v);
});

$('report-btn').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'report', url: currentUrl, category: $('report-category').value });
  show(currentUrl);
});

$('unreport-btn').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'unreport', url: currentUrl });
  show(currentUrl);
});

async function showListInfo() {
  const info = await chrome.runtime.sendMessage({ type: 'listInfo' });
  if (!info?.ok) return;
  $('list-info').textContent =
    `詐騙網站名單：165 公開資料 ${info.dataMonth ?? ''}，共 ${Number(info.count).toLocaleString('zh-TW')} 筆`;
}

$('open-options').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

resolveInitialUrl().then(show);
showListInfo();

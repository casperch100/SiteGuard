const $ = (id) => document.getElementById(id);
const send = (msg) => chrome.runtime.sendMessage(msg);

async function refresh() {
  const [settings, stats, info] = await Promise.all([send({ type: 'getSettings' }), send({ type: 'stats' }), send({ type: 'listInfo' })]);
  $('domain-age').checked = !!settings.domainAgeLookup;
  $('reports-count').textContent = `${stats.reports} 個網站`;
  $('ages-count').textContent = `${stats.domainAges} 個網域`;
  $('clear-reports').disabled = !stats.reports;
  $('clear-ages').disabled = !stats.domainAges;
  if (info?.ok) $('list-info').textContent = `165 公開資料 ${info.dataMonth ?? ''}，共 ${Number(info.count).toLocaleString('zh-TW')} 筆`;
  $('version').textContent = `版本 ${chrome.runtime.getManifest().version}`;
}

$('domain-age').addEventListener('change', async (e) => {
  await send({ type: 'setSettings', settings: { domainAgeLookup: e.target.checked } });
  $('saved').hidden = false;
  setTimeout(() => { $('saved').hidden = true; }, 1500);
});

$('clear-reports').addEventListener('click', async () => {
  if (!confirm('確定要清除所有回報紀錄嗎？清除後無法復原。')) return;
  await send({ type: 'clearData', what: 'reports' });
  refresh();
});

$('clear-ages').addEventListener('click', async () => {
  await send({ type: 'clearData', what: 'domainAges' });
  refresh();
});

refresh();

const params = new URLSearchParams(location.search);
const url = params.get('url') || '';
const $ = (id) => document.getElementById(id);

async function init() {
  let host = url;
  try { host = new URL(url).hostname; } catch {}
  $('host').textContent = host || '（未知網址）';
  $('proceed-host').textContent = host;

  const result = await chrome.runtime.sendMessage({ type: 'check', url, lookup: true });
  if (result?.ok) {
    if (result.category) {
      $('category').textContent = result.category;
      $('category').hidden = false;
    }
    $('reasons').replaceChildren(...result.reasons.map((r) => {
      const li = document.createElement('li');
      li.textContent = r.text;
      return li;
    }));
  }
}

$('back').addEventListener('click', async () => {
  if (history.length > 1) {
    history.back();
  } else {
    const tab = await chrome.tabs.getCurrent();
    chrome.tabs.update(tab.id, { url: 'chrome://newtab' });
  }
});

/** 只允許前往 http(s) 網址（避免 javascript: 等網址在擴充功能頁面中執行） */
function safeTarget(raw) {
  try {
    const u = new URL(raw);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}

$('proceed').addEventListener('click', async () => {
  const target = safeTarget(url);
  if (!target) {
    $('proceed').disabled = true;
    $('proceed').textContent = '這不是可以前往的網址';
    return;
  }
  await chrome.runtime.sendMessage({ type: 'bypass', url: target });
  location.href = target;
});

init();

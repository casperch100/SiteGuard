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

$('proceed').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'bypass', url });
  location.href = url;
});

init();

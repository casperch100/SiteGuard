// ============================================================
// 「判斷錯了？」：產生預先填好的 GitHub Issue 網址（純函式）
// 只帶網域、判斷結果與判斷原因，不帶完整網址（路徑、查詢參數可能含個人資料）。
// 使用者點連結後會在 GitHub 看到表單，可以修改，按下送出才會公開。
// ============================================================
export const ISSUES_NEW = 'https://github.com/casperch100/SiteGuard/issues/new';

const LEVEL_OPTION = { danger: '危險（跳出警告頁）', suspicious: '可疑（Popup 或連結標示為可疑）' };
const MAX_REASONS = 6;

/** 把網域的 . 改成 [.]，貼在 Issue 裡不會變成可點擊的連結 */
export function defang(host) {
  return String(host).replace(/\./g, '[.]');
}

/**
 * 回報網址。result 是 assessUrl 的結果；version 是擴充功能版本。
 * - 判為可疑或危險 → 「回報誤判」表單
 * - 其他 → 「回報漏抓」表單（網域改成 [.] 的寫法）
 * 回傳 null 表示不提供回報（例如無法判斷的網址、可信任網站）。
 */
export function feedbackUrl(result, version = '') {
  if (!result?.ok || !result.host || result.level === 'safe') return null;
  const p = new URLSearchParams();
  if (result.level === 'danger' || result.level === 'suspicious') {
    // 165 名單或自己回報的網站不是 SiteGuard 的判斷，誤判要向 165 反映，不在這裡收
    if (result.listed165 || result.reported) return null;
    p.set('template', 'false-positive.yml');
    p.set('title', `[誤判] ${result.host}`);
    p.set('domain', result.host);
    p.set('level', LEVEL_OPTION[result.level]);
    p.set('reasons', (result.reasons || []).filter((r) => r.weight > 0).slice(0, MAX_REASONS)
      .map((r) => `- ${r.text}`).join('\n'));
  } else {
    p.set('template', 'missed-scam.yml');
    p.set('title', `[漏抓] ${defang(result.host)}`);
    p.set('domain', defang(result.host));
  }
  if (version) p.set('version', version);
  return `${ISSUES_NEW}?${p}`;
}

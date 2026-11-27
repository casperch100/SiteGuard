// ============================================================
// 離線評估：用和擴充功能「同一份」偵測引擎，計算偵測率與誤判率。
// 純函式，Node（tools/eval/evaluate.mjs）與瀏覽器（eval/run.html）共用。
// ============================================================
import { assessUrl } from '../../src/lib/risk.js';

export const TARGET = { detection: 0.5, falsePositive: 0.01 };

/** 解析本專案產生的 CSV（支援雙引號欄位） */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') q = false;
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  const [header, ...data] = rows;
  return data.map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ''])));
}

const flagged = (level) => level === 'danger' || level === 'suspicious';
const pct = (x) => (Number.isFinite(x) ? `${(x * 100).toFixed(1)}%` : '—');

function rate(results) {
  const n = results.length;
  const hit = results.filter((r) => flagged(r.level)).length;
  const danger = results.filter((r) => r.level === 'danger').length;
  return { n, hit, danger, rate: n ? hit / n : NaN, dangerRate: n ? danger / n : NaN };
}

function ageDays(row, now) {
  if (!row.reg_date) return null;
  const ref = row.collected_at ? new Date(row.collected_at) : now;
  return Math.round((ref - new Date(row.reg_date)) / 86400000);
}

/**
 * @param {object} p
 * @param {object[]} p.positives  eval/data/positives.csv 的列
 * @param {string[]} p.negatives  正常網域
 * @param {{hosts: Map, meta: object}|null} p.blocklist  165 名單（可為 null，代表只用規則）
 * @param {number} [p.windowDays]  只評估最近幾天收集的詐騙網域
 * @param {Date} [p.now]
 */
export function evaluate({ positives, negatives, blocklist = null, windowDays = 28, now = new Date(), negativeAges = null }) {
  const since = new Date(now.getTime() - windowDays * 86400000);
  // 使用 165 名單時，排除來源就是 165 的樣本：它們本來就在名單裡，算進去會高估（循環論證）
  const pos = positives.filter((r) => (!r.collected_at || new Date(r.collected_at) >= since)
    && !(blocklist && r.source === '165'));

  // 收集當下查到的註冊日期，提供給引擎（第 3 步加入網域年齡規則後才會用到）
  const ageByReg = new Map();
  for (const r of pos) {
    const a = ageDays(r, now);
    if (a !== null) ageByReg.set(r.registrable, a);
  }
  const opts = { blocklist, domainAgeDays: (registrable) => ageByReg.get(registrable) ?? null };

  const posResults = pos.map((r) => ({ ...r, ...pick(assessUrl(`https://${r.host}/`, opts)) }));

  // 正常網域：抽樣查過註冊日期的，也套用網域年齡規則（避免低估誤判率）
  const negAgeRef = negativeAges?.checkedAt ? new Date(negativeAges.checkedAt) : now;
  const negAge = (reg) => {
    const d = negativeAges?.ages?.[reg];
    return d ? Math.round((negAgeRef - new Date(d)) / 86400000) : null;
  };
  const negResults = negatives.map((h) => {
    const r = assessUrl(`https://${h}/`, { blocklist, domainAgeDays: negAge });
    return { host: h, aged: typeof negAge(r.registrable) === 'number', ...pick(r) };
  });
  const agedNeg = negResults.filter((r) => r.aged);

  const groups = (key) => {
    const m = new Map();
    for (const r of posResults) {
      const k = key(r);
      if (!m.has(k)) m.set(k, []);
      m.get(k).push(r);
    }
    return [...m].map(([k, rs]) => ({ key: k, ...rate(rs) })).sort((a, b) => b.n - a.n);
  };

  const nonPlatform = pos.filter((r) => r.platform !== '1');
  const ages = nonPlatform.map((r) => ageDays(r, now)).filter((a) => a !== null).sort((a, b) => a - b);

  return {
    generatedAt: now.toISOString(),
    windowDays,
    blocklist: blocklist ? `${blocklist.meta?.dataMonth}（${blocklist.hosts.size} 筆）` : '不使用',
    detection: rate(posResults),
    falsePositive: rate(negResults),
    falsePositiveAged: rate(agedNeg),
    agedNegatives: agedNeg.length,
    bySource: groups((r) => r.source),
    byPlatform: groups((r) => (r.platform === '1' ? '共用平台子網域' : '獨立網域')),
    byAgeKnown: groups((r) => (r.reg_date ? '查得到註冊日期' : '查不到註冊日期')),
    age: {
      withDate: ages.length,
      total: nonPlatform.length,
      median: ages.length ? ages[Math.floor(ages.length / 2)] : null,
      le30: ages.filter((a) => a <= 30).length,
      le90: ages.filter((a) => a <= 90).length,
      le365: ages.filter((a) => a <= 365).length,
    },
    rdapStatus: count(nonPlatform.map((r) => r.rdap_status || '—')),
    missedExamples: posResults.filter((r) => !flagged(r.level)).slice(0, 15).map((r) => r.host),
    falsePositiveExamples: negResults.filter((r) => flagged(r.level)).slice(0, 30)
      .map((r) => `${r.host}（${r.level} ${r.score}：${r.reasons}）`),
  };
}

function pick(r) {
  return {
    level: r.ok ? r.level : 'invalid',
    score: r.score ?? 0,
    reasons: (r.reasons || []).filter((x) => x.weight > 0).map((x) => x.text).join('；'),
  };
}

function count(arr) {
  const m = {};
  for (const x of arr) m[x] = (m[x] || 0) + 1;
  return m;
}

/** 產生 Markdown 報告 */
/** 最近的收集紀錄（eval/data/collect-log.csv）轉成報告段落 */
export function collectLogSection(logText, maxRows = 10) {
  if (!logText) return [];
  const rows = parseCsv(logText);
  if (!rows.length) return [];
  const recent = rows.slice(-maxRows).reverse();
  const lines = ['## 最近的資料收集', ''];

  // 連續兩次以上在 GitHub Actions 上 PhishTank 失敗，或下載成功卻沒有任何最近通報 → 提醒
  const ci = rows.filter((r) => r.runner === 'github-actions' && r.source === 'phishtank').slice(-2);
  if (ci.length === 2 && ci.every((r) => r.status !== 'ok')) {
    lines.push(`> ⚠️ GitHub Actions 上最近兩次下載 PhishTank 都失敗：${ci[1].note || '原因不明'}`, '');
  } else if (ci.length === 2 && ci.every((r) => r.status === 'ok' && Number(r.fresh) === 0)) {
    lines.push('> ⚠️ GitHub Actions 上最近兩次下載 PhishTank 成功，但都沒有最近 72 小時的通報，資料可能過期或被限制。', '');
  }

  lines.push('| 時間（UTC） | 執行環境 | 來源 | 結果 | 下載筆數 | 近期通報 | 新增網域 | 查到註冊日期 | 備註 |', '|---|---|---|---|---|---|---|---|---|');
  for (const r of recent) {
    const ok = r.status === 'ok' ? '✅ 成功' : '❌ 失敗';
    const env = r.runner === 'github-actions' ? 'GitHub Actions' : '本機';
    lines.push(`| ${r.run_at.replace('T', ' ').slice(0, 16)} | ${env} | ${r.source} | ${ok} | ${r.downloaded} | ${r.fresh} | ${r.new_domains} | ${r.rdap_ok} | ${(r.note || '').replace(/\|/g, '／')} |`);
  }
  lines.push('', '「近期通報」：PhishTank 是最近 72 小時內通報、已驗證且仍在線的網址數；165 是最新月份新增的網域數。「新增網域」不含之前已收集過的。', '');
  return lines;
}

export function toMarkdown(results, { collectLog = '' } = {}) {
  const [main, ...others] = results;
  const ok = (v, t, lower) => (lower ? v <= t : v >= t) ? '✅' : '❌';
  const lines = [];
  lines.push('# SiteGuard 偵測評估報告', '');
  lines.push(`> 產生時間：${main.generatedAt.replace('T', ' ').slice(0, 16)} UTC　評估範圍：最近 ${main.windowDays} 天收集的詐騙網域`, '');
  lines.push('## 是否達標', '');
  lines.push('| 指標 | 目標 | 只用規則 | 加上 165 名單 |', '|---|---|---|---|');
  const withList = others[0] ?? main;
  lines.push(`| 偵測率（可疑＋危險） | ≥ ${pct(TARGET.detection)} | ${pct(main.detection.rate)} ${ok(main.detection.rate, TARGET.detection)} | ${pct(withList.detection.rate)} ${ok(withList.detection.rate, TARGET.detection)} |`);
  lines.push(`| 其中判為「危險」 | — | ${pct(main.detection.dangerRate)} | ${pct(withList.detection.dangerRate)} |`);
  lines.push(`| 誤判率（正常網站被判可疑或危險） | ≤ ${pct(TARGET.falsePositive)} | ${pct(main.falsePositive.rate)} ${ok(main.falsePositive.rate, TARGET.falsePositive, true)} | ${pct(withList.falsePositive.rate)} ${ok(withList.falsePositive.rate, TARGET.falsePositive, true)} |`);
  if (main.agedNegatives) {
    lines.push(`| 誤判率（只看查得到註冊日期的 ${main.agedNegatives} 個正常網站） | ≤ ${pct(TARGET.falsePositive)} | ${pct(main.falsePositiveAged.rate)} ${ok(main.falsePositiveAged.rate, TARGET.falsePositive, true)} | ${pct(withList.falsePositiveAged.rate)} ${ok(withList.falsePositiveAged.rate, TARGET.falsePositive, true)} |`);
  }
  lines.push(`| 樣本數 | — | 詐騙 ${main.detection.n}／正常 ${main.falsePositive.n} | 詐騙 ${withList.detection.n}／正常 ${withList.falsePositive.n} |`, '');
  lines.push('「只用規則」代表新詐騙網站還沒進任何名單時的表現，是第一階段的主要目標。「加上 165 名單」不計入來源是 165 的樣本（它們本來就在名單中）。', '');

  lines.push(...collectLogSection(collectLog));

  lines.push('## 偵測率細項（只用規則）', '');
  lines.push('| 分組 | 樣本 | 偵測率 | 危險 |', '|---|---|---|---|');
  for (const g of [...main.bySource, ...main.byPlatform, ...main.byAgeKnown]) lines.push(`| ${g.key} | ${g.n} | ${pct(g.rate)} | ${pct(g.dangerRate)} |`);
  lines.push('');

  const a = main.age;
  lines.push('## 網域年齡（獨立網域，收集當下查詢）', '');
  lines.push(`- 查得到註冊日期：${a.withDate}／${a.total}　（RDAP 狀態：${Object.entries(main.rdapStatus).map(([k, v]) => `${k} ${v}`).join('、')}）`);
  if (a.withDate) {
    lines.push(`- 中位數：${a.median} 天`);
    lines.push(`- 30 天內：${pct(a.le30 / a.withDate)}　90 天內：${pct(a.le90 / a.withDate)}　一年內：${pct(a.le365 / a.withDate)}`);
  }
  lines.push('');

  lines.push('## 漏抓的詐騙網域（範例）', '', ...main.missedExamples.map((h) => `- \`${h}\``), '');
  lines.push(`## 被誤判的正常網站（共 ${main.falsePositive.hit} 個，列出前 30 個）`, '');
  lines.push(...(main.falsePositiveExamples.length ? main.falsePositiveExamples.map((s) => `- ${s}`) : ['（無）']), '');
  lines.push('---', '資料來源：[PhishTank](https://phishtank.org/)（Cisco Talos）、內政部警政署 165 反詐騙諮詢專線、[Tranco](https://tranco-list.eu/) 熱門網站排行。');
  return lines.join('\n') + '\n';
}

/** history.csv 的一列 */
export function historyRow(results) {
  const [main, withList = main] = results;
  return [main.generatedAt.slice(0, 10), main.windowDays, main.detection.n, main.detection.rate.toFixed(4),
    main.detection.dangerRate.toFixed(4), main.falsePositive.n, main.falsePositive.rate.toFixed(4),
    withList.detection.rate.toFixed(4),
    Number.isFinite(main.falsePositiveAged.rate) ? main.falsePositiveAged.rate.toFixed(4) : ''].join(',');
}
export const HISTORY_HEADER = 'date,window_days,positives,detection_rules,danger_rules,negatives,false_positive_rules,detection_with_165,false_positive_aged_sample';

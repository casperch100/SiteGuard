// ============================================================
// 165 涉詐網站名單：解析、查詢、從政府開放資料更新
// 純函式，可在 Service Worker 與測試中共用
// ============================================================

/** 「遭停止解析涉詐網站」資料集（每月更新）的 CSV 下載網址 */
export const SUSPENDED_CSV_URL =
  'https://opdadm.moi.gov.tw/api/v1/no-auth/resource/api/dataset/29E8E643-88ED-4952-B21E-BD42A3B7108C/resource/01EFB21E-DB91-4EDF-843F-F45923BBFA1D/download';

export const SOURCE_NAME = '內政部警政署 165 反詐騙諮詢專線';

/** 原始資料中的錯字與無意義分類（和 tools/update_165.rb 的 SECTOR_FIX 保持一致） */
const SECTOR_FIX = { 金融保線: '金融保險', 金融保健: '金融保險', 不詳: '' };

export function sectorLabel(sector) {
  let s = String(sector ?? '').trim();
  if (s in SECTOR_FIX) s = SECTOR_FIX[s];
  return s ? `涉詐網站（${s}）` : '涉詐網站';
}

/** 和 tools/update_165.rb 的 normalize_host 保持一致 */
export function normalizeHost(s) {
  let h = String(s ?? '').trim().toLowerCase();
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[/?#:\\\s].*$/, '').replace(/\.$/, '').replace(/^www\./, '');
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(h) ? h : null;
}

/**
 * 解析名單文字（每行「主機名稱<TAB>分類代碼」）。
 * @returns {{ hosts: Map<string, number>, meta: object }}
 */
export function parseList(text, meta) {
  const hosts = new Map();
  let start = 0;
  while (start < text.length) {
    let end = text.indexOf('\n', start);
    if (end === -1) end = text.length;
    const tab = text.indexOf('\t', start);
    if (tab > start && tab < end) hosts.set(text.slice(start, tab), Number(text.slice(tab + 1, end)) || 0);
    start = end + 1;
  }
  return { hosts, meta };
}

/** 把 Map 轉回名單文字（儲存用） */
export function serializeList(hosts) {
  let out = '';
  for (const [h, i] of hosts) out += `${h}\t${i}\n`;
  return out;
}

/**
 * 查詢主機名稱：先比對完整主機名稱，再逐層比對上層網域（到可註冊網域為止）。
 * 例如名單有 scam.top，則 a.b.scam.top 也會命中；但名單上的 x.workers.dev 不會影響其他 workers.dev 子網域。
 */
export function lookupHost(list, host, registrable) {
  if (!list) return null;
  let h = host.replace(/^www\./, '');
  for (;;) {
    const idx = list.hosts.get(h);
    if (idx !== undefined) {
      const cat = list.meta?.categories?.[idx] ?? { label: '涉詐網站', source: 'suspended' };
      return { category: cat.label, source: cat.source, matched: h };
    }
    if (!registrable || h === registrable) return null;
    const dot = h.indexOf('.');
    if (dot === -1) return null;
    h = h.slice(dot + 1);
    if (h.length < registrable.length) return null;
  }
}

/** 切分一行 CSV：支援以雙引號包住、內含逗號或 "" 跳脫的欄位（RFC 4180） */
export function splitCsvLine(line) {
  const out = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"' && field === '') quoted = true;
    else if (c === ',') { out.push(field); field = ''; }
    else field += c;
  }
  out.push(field);
  return out;
}

/** 民國年月（例如 11510）轉成「2026/10」 */
export function rocMonthLabel(ym) {
  const m = /^(\d{2,3})(\d{2})$/.exec(String(ym ?? '').trim());
  return m ? `${Number(m[1]) + 1911}/${m[2]}` : null;
}

/**
 * 把最新的「遭停止解析涉詐網站」CSV 合併進現有名單。
 * 欄位：民國年月,網域,網站性質,法律依據,聲請單位
 * @param {string} csv  下載的 CSV 文字
 * @param {{hosts: Map, meta: object}} base  目前的名單（內建快照或上次更新的結果）
 * @param {(host: string) => boolean} isAllowed  白名單判斷，命中的不列入
 * @returns {{ hosts: Map, meta: object, added: number }}
 */
export function mergeSuspendedCsv(csv, base, isAllowed = () => false) {
  const lines = csv.replace(/^﻿/, '').split(/\r?\n/);
  const header = (lines.shift() || '').split(',').map((s) => s.trim());
  const col = (name) => header.indexOf(name);
  const iMonth = col('民國年月');
  const iHost = col('網域');
  const iSector = col('網站性質');
  if (iHost === -1) throw new Error('CSV 格式不符：找不到「網域」欄位');

  const categories = [...(base.meta?.categories ?? [])];
  const catIndex = (label) => {
    let i = categories.findIndex((c) => c.label === label && c.source === 'suspended');
    if (i === -1) {
      categories.push({ label, source: 'suspended' });
      i = categories.length - 1;
    }
    return i;
  };

  const hosts = new Map(base.hosts);
  let added = 0;
  let latest = '';
  for (const line of lines) {
    if (!line) continue;
    const f = splitCsvLine(line).map((s) => s.trim());
    const host = normalizeHost(f[iHost]);
    if (!host) continue;
    if (iMonth !== -1 && f[iMonth] > latest) latest = f[iMonth];
    if (hosts.has(host) || isAllowed(host)) continue; // 已在名單中的不用再做白名單判斷
    hosts.set(host, catIndex(sectorLabel(iSector !== -1 ? f[iSector] : '')));
    added++;
  }
  if (!latest) throw new Error('CSV 沒有任何資料');

  const meta = {
    ...base.meta,
    categories,
    count: hosts.size,
    dataMonth: rocMonthLabel(latest) ?? base.meta?.dataMonth,
    updatedAt: new Date().toISOString(),
  };
  return { hosts, meta, added };
}

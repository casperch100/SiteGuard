import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessUrl, parseTarget, levenshtein, isAllowedHost } from '../src/lib/risk.js';
import { parseList, serializeList, lookupHost, mergeSuspendedCsv, normalizeHost, rocMonthLabel, sectorLabel } from '../src/lib/blocklist.js';

// 測試用的小名單（網域取自 165 公開資料）
const META = {
  dataMonth: '2026/10',
  categories: [
    { label: '涉詐網站（運輸倉儲）', source: 'suspended' },
    { label: '假投資（博弈）網站', source: 'invest' },
  ],
};
const LIST = parseList('myship-711-com-tw.cfd\t0\nycoinit.com\t1\nfvips.ctoserver0905.workers.dev\t0\n', META);
const level = (u, opts = {}) => assessUrl(u, { blocklist: LIST, ...opts }).level;

test('白名單與政府網站判定為安全', () => {
  for (const u of ['https://shopee.tw/', 'https://www.cathaybk.com.tw/x', 'https://www.post.gov.tw/', 'google.com', 'https://mail.google.com/']) {
    assert.equal(level(u), 'safe', u);
  }
});

test('165 名單命中判定為危險，並附分類與資料來源', () => {
  const r = assessUrl('https://myship-711-com-tw.cfd/order', { blocklist: LIST });
  assert.equal(r.level, 'danger');
  assert.equal(r.category, '涉詐網站（運輸倉儲）');
  assert.equal(r.listed165, true);
  assert.ok(r.reasons[0].text.includes('165'), r.reasons[0].text);
  assert.ok(r.reasons[0].text.includes('2026/10'), r.reasons[0].text);
  assert.equal(level('https://www.ycoinit.com/'), 'danger');
});

test('165 名單：子網域命中，但共用平台的其他子網域不受影響', () => {
  assert.equal(level('https://a.b.myship-711-com-tw.cfd/'), 'danger');
  assert.equal(level('https://fvips.ctoserver0905.workers.dev/'), 'danger');
  assert.equal(level('https://my-app.workers.dev/'), 'unknown');
});

test('沒有名單時仍能用規則判斷', () => {
  assert.equal(assessUrl('https://myship-711-com-tw.cfd/').level, 'unknown');
  assert.equal(assessUrl('https://line-login-secure.com/').level, 'suspicious');
});

test('仿冒網址由規則判定為危險', () => {
  // 品牌名稱 40 + 可疑字詞 20 + 可疑後綴 15
  assert.equal(level('https://line-login-secure.top/'), 'danger');
  // 品牌名稱 40 + 可疑字詞 20 + 可疑後綴 15 + 連字號過多 10
  assert.equal(level('https://esunbank-tw-verify-login.online/'), 'danger');
});

test('可疑但未達危險', () => {
  assert.equal(level('https://paypa1.com/signin'), 'suspicious');
  assert.equal(level('https://shopee.top/'), 'suspicious');
  assert.equal(level('http://203.0.113.45/bank/login'), 'suspicious');
  assert.equal(level('https://www.cathaybk.com.tw@evil-site.example/'), 'suspicious');
});

test('一般網站不誤判', () => {
  for (const u of ['https://new-coffee-shop.com/', 'https://www.onlinebanking-news.org/', 'https://pineapple.com/', 'https://airline.com/', 'http://localhost:8000/']) {
    assert.equal(level(u), 'unknown', u);
  }
});

test('使用者回報會覆蓋判斷', () => {
  const reports = { 'new-coffee-shop.com': { category: '假購物' } };
  const r = assessUrl('https://www.new-coffee-shop.com/', { reports, blocklist: LIST });
  assert.equal(r.level, 'danger');
  assert.equal(r.reported, true);
});

test('無效輸入', () => {
  assert.equal(assessUrl('').ok, false);
  assert.equal(assessUrl('chrome://extensions').ok, false);
  assert.equal(assessUrl('javascript:alert(1)').ok, false);
});

test('網域解析', () => {
  assert.equal(parseTarget('a.b.cathaybk.com.tw').registrable, 'cathaybk.com.tw');
  assert.equal(parseTarget('https://x.y.example.com').registrable, 'example.com');
  assert.equal(levenshtein('paypal', 'paypa'), 1);
});

test('名單工具：正規化、民國年月、分類名稱、序列化', () => {
  assert.equal(normalizeHost(' HTTPS://WWW.Scam.Top/path?x=1 '), 'scam.top');
  assert.equal(normalizeHost('bitgin'), null);
  assert.equal(rocMonthLabel('11510'), '2026/10');
  assert.equal(sectorLabel('金融保線'), '涉詐網站（金融保險）');
  assert.equal(sectorLabel('不詳'), '涉詐網站');
  assert.equal(parseList(serializeList(LIST.hosts), META).hosts.size, 3);
  assert.equal(lookupHost(LIST, 'ycoinit.com', 'ycoinit.com').source, 'invest');
});

test('合併最新 CSV：新增網域、略過白名單、更新資料月份', () => {
  const csv = '﻿民國年月,網域,網站性質,法律依據,聲請單位\r\n'
    + '11511,new-scam-shop.top,電子商務,詐欺犯罪危害防制條例,刑事警察局詐欺犯罪防制中心\r\n'
    + '11511,www.myship-711-com-tw.cfd,運輸倉儲,詐欺犯罪危害防制條例,刑事警察局詐欺犯罪防制中心\r\n'
    + '11511,play.google.com,資訊服務,詐欺犯罪危害防制條例,刑事警察局詐欺犯罪防制中心\r\n';
  const merged = mergeSuspendedCsv(csv, LIST, isAllowedHost);
  assert.equal(merged.added, 1);
  assert.equal(merged.meta.dataMonth, '2026/11');
  assert.equal(merged.hosts.has('play.google.com'), false);
  const r = assessUrl('https://new-scam-shop.top/', { blocklist: { hosts: merged.hosts, meta: merged.meta } });
  assert.equal(r.category, '涉詐網站（電子商務）');
  assert.throws(() => mergeSuspendedCsv('a,b\n1,2\n', LIST), /網域/);
});

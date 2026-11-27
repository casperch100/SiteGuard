import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessUrl, parseTarget, levenshtein, isAllowedHost, domainForAgeLookup } from '../src/lib/risk.js';
import { rdapUrl, parseRegistrationDate, ageInDays, isFresh } from '../src/lib/rdap.js';
import { parseList, serializeList, lookupHost, mergeSuspendedCsv, normalizeHost, rocMonthLabel, sectorLabel, splitCsvLine } from '../src/lib/blocklist.js';

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

test('網域年齡：新註冊網域加分，舊網域不加分', () => {
  const age = (days) => () => days;
  const r = assessUrl('https://tuoho.shop/', { domainAgeDays: age(12) });
  assert.equal(r.ageDays, 12);
  assert.ok(r.reasons.some((x) => x.text.includes('12 天')), JSON.stringify(r.reasons));
  assert.equal(r.level, 'suspicious'); // 40（30 天內）+ 15（可疑後綴）
  assert.equal(assessUrl('https://tuoho.shop/', { domainAgeDays: age(60) }).score, 45);
  assert.equal(assessUrl('https://tuoho.shop/', { domainAgeDays: age(400) }).score, 15);
  assert.equal(assessUrl('https://tuoho.shop/', { domainAgeDays: () => null }).score, 15);
  // 新網域 + 冒用品牌 + 可疑字詞 → 危險
  assert.equal(assessUrl('https://line-login.com/', { domainAgeDays: age(5) }).level, 'danger');
  // 正常的舊網站不受影響
  assert.equal(assessUrl('https://new-coffee-shop.com/', { domainAgeDays: age(3000) }).level, 'unknown');
});

test('網域年齡：哪些網址需要查詢', () => {
  assert.equal(domainForAgeLookup('https://a.b.tuoho.shop/x'), 'tuoho.shop');
  assert.equal(domainForAgeLookup('https://www.example.com.tw/'), 'example.com.tw');
  assert.equal(domainForAgeLookup('https://shopee.tw/'), null);           // 白名單
  assert.equal(domainForAgeLookup('https://www.post.gov.tw/'), null);     // 政府網站
  assert.equal(domainForAgeLookup('http://203.0.113.45/'), null);         // IP
  assert.equal(domainForAgeLookup('http://localhost:8000/'), null);       // 本機
  assert.equal(domainForAgeLookup('https://myship-711-com-tw.cfd/', { blocklist: LIST }), null); // 已在 165 名單
});

test('RDAP：查詢網址、解析註冊日期、天數與快取', () => {
  const bootstrap = { tlds: { com: 'https://rdap.verisign.com/com/v1/', tw: 'https://ccrdap.twnic.tw/tw' } };
  assert.equal(rdapUrl(bootstrap, 'example.com'), 'https://rdap.verisign.com/com/v1/domain/example.com');
  assert.equal(rdapUrl(bootstrap, 'example.com.tw'), 'https://ccrdap.twnic.tw/tw/domain/example.com.tw');
  assert.equal(rdapUrl(bootstrap, 'example.zzz'), null);
  assert.equal(parseRegistrationDate({ events: [{ eventAction: 'last changed', eventDate: '2026-01-01T00:00:00Z' },
    { eventAction: 'registration', eventDate: '2026-11-20T08:15:00Z' }] }), '2026-11-20');
  assert.equal(parseRegistrationDate({ events: [] }), null);
  const now = Date.parse('2026-11-27T12:00:00Z');
  assert.equal(ageInDays('2026-11-20', now), 7);
  assert.equal(isFresh({ regDate: '2026-11-20', checkedAt: now - 29 * 86400000 }, now), true);
  assert.equal(isFresh({ regDate: '2026-11-20', checkedAt: now - 31 * 86400000 }, now), false);
  assert.equal(isFresh({ regDate: null, checkedAt: now - 2 * 86400000 }, now), false); // 查不到的 1 天後重試
});

test('Punycode（國際化字元）網域加分', () => {
  const r = assessUrl('https://xn--pypal-4ve.com/');
  assert.ok(r.reasons.some((x) => x.text.includes('Punycode')), JSON.stringify(r.reasons));
  assert.equal(r.level, 'suspicious');
});

test('回報過的網站不查詢註冊日期', () => {
  const reports = { 'some-shop.xyz': { category: '假購物' } };
  assert.equal(domainForAgeLookup('https://some-shop.xyz/', { reports }), null);
  assert.equal(domainForAgeLookup('https://other-shop.xyz/', { reports }), 'other-shop.xyz');
});

test('CSV：雙引號包住、含逗號或 "" 的欄位', () => {
  assert.deepEqual(splitCsvLine('11511,a.top,電子商務,條例,單位'), ['11511', 'a.top', '電子商務', '條例', '單位']);
  assert.deepEqual(splitCsvLine('11511,b.top,"金融保險,投資","含 ""引號"" 的欄位",單位'),
    ['11511', 'b.top', '金融保險,投資', '含 "引號" 的欄位', '單位']);
  const csv = '民國年月,網域,網站性質,法律依據,聲請單位\n11511,quoted-scam.top,"金融保險,投資",條例,單位\n';
  const merged = mergeSuspendedCsv(csv, LIST, isAllowedHost);
  assert.equal(merged.added, 1);
  const r = assessUrl('https://quoted-scam.top/', { blocklist: { hosts: merged.hosts, meta: merged.meta } });
  assert.equal(r.category, '涉詐網站（金融保險,投資）');
});

test('二層公眾後綴（和評估工具一致）', () => {
  assert.equal(parseTarget('https://shop.example.com.br/').registrable, 'example.com.br');
  assert.equal(parseTarget('https://a.b.example.co.kr/').registrable, 'example.co.kr');
});

test('Demo 頁的保留網域仍會被規則判為可疑', () => {
  assert.equal(level('https://paypa1.example/signin'), 'suspicious');
  assert.equal(level('https://shopee.example/'), 'suspicious');
});

test('共用平台：以子網域為單位，不查網域年齡', () => {
  const t = parseTarget('https://a.scam-shop.github.io/login');
  assert.equal(t.registrable, 'scam-shop.github.io');
  assert.equal(t.platform, true);
  assert.equal(parseTarget('https://x.my.canva.site/').registrable, 'x.my.canva.site'); // 最長的平台後綴優先
  assert.equal(parseTarget('https://github.io/').platform, false);
  assert.equal(domainForAgeLookup('https://scam-shop.github.io/'), null);
  // 回報一個子網域，不會連帶標記同平台的其他網站
  const reports = { 'scam-shop.github.io': { category: '假購物' } };
  assert.equal(assessUrl('https://scam-shop.github.io/', { reports }).level, 'danger');
  assert.equal(assessUrl('https://someone-blog.github.io/', { reports }).level, 'unknown');
});

test('名單正規化：去掉網址中「@」前面的部分', () => {
  assert.equal(normalizeHost('https://user:pw@Evil-Site.top/x'), 'evil-site.top');
});

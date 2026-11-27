import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessUrl, parseTarget, levenshtein, isAllowedHost, domainForAgeLookup, decodePunycodeLabel, idnInfo } from '../src/lib/risk.js';
import { feedbackUrl, defang, safeReasonText } from '../src/lib/feedback.js';
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
  assert.equal(r.level, 'danger'); // 40（30 天內）+ 15（可疑後綴）+ 15（兩者同時出現）
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
  assert.equal(isFresh({ regDate: null, checkedAt: now - 12 * 3600000 }, now), true);  // 1 天內不重查
});

test('Punycode（國際化字元）網域加分', () => {
  const r = assessUrl('https://xn--pypal-4ve.com/');
  assert.ok(r.reasons.some((x) => x.text.includes('Punycode')), JSON.stringify(r.reasons));
  assert.equal(r.level, 'danger'); // 混用西里爾字母，換回拉丁字母後就是 paypal.com
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

test('網址帳號欄位有錯誤編碼時不會出錯', () => {
  const t = parseTarget('https://user%80@example.com/');
  assert.equal(t.userInfo, 'user%80');
  assert.equal(assessUrl('http://www.bank.com%FF@phish.example/').ok, true);
});

test('品牌自己的網域不誤判', () => {
  for (const u of ['https://www.google.de/', 'https://google.co.jp/', 'https://google.com.py/', 'https://blog.google/',
    'https://www.googletagmanager.com/', 'https://edge.apple/', 'https://cdn-apple.com/', 'https://shopee.co.id/',
    'https://shopee.com.my/', 'https://static.line-scdn.net/', 'https://paypal.me/x', 'https://www.cathaylife.com.tw/',
    'https://www.post-gazette.com/', 'https://pcloud.com/', 'https://cloud.com/', 'https://huaweicloud.com/', 'https://hicloud.com/']) {
    assert.ok(!['suspicious', 'danger'].includes(level(u)), u);
  }
});

test('仿冒品牌仍會被抓到', () => {
  for (const u of ['https://google-login.top/', 'https://shopee-tw.xyz/', 'https://cathaybk-verify.com/', 'https://twpost-pay.com/',
    'https://line-login-secure.com/', 'https://icloud-find.com/', 'https://paypa1.com/']) {
    assert.ok(['suspicious', 'danger'].includes(level(u)), u);
  }
});

test('國際化網域：拉丁字母混用相似字元才加重分數', () => {
  assert.equal(decodePunycodeLabel('xn--pypal-4ve'), 'pаypal');        // а 是西里爾字母
  assert.equal(decodePunycodeLabel('xn--80ak6aa92e'), 'аррӏе');        // 整段西里爾字元拼成 apple
  assert.equal(idnInfo('xn--pypal-4ve.com').kind, 'mixed');
  assert.equal(idnInfo('xn--80ak6aa92e.com').kind, 'mixed');
  assert.equal(idnInfo('xn--cksr0a.tw').kind, 'native');             // 中文網域
  assert.equal(level('https://xn--cksr0a.tw/'), 'unknown');
  assert.equal(idnInfo('xn--ngstr-lra8j.com').kind, 'native');       // ångström：重音字母不算混用
  assert.equal(level('https://xn--80ak6aa92e.com/'), 'danger');       // 看起來是 apple.com
});

test('剛註冊＋詐騙常見後綴才升為危險', () => {
  const at = (days) => ({ domainAgeDays: () => days });
  assert.equal(level('https://brand-new-shop.top/', at(5)), 'danger');      // 40 + 15 + 15
  assert.equal(level('https://brand-new-shop.top/', at(29)), 'danger');
  assert.equal(level('https://brand-new-shop.top/', at(45)), 'suspicious');  // 超過 30 天
  assert.equal(level('https://brand-new-shop.com/', at(5)), 'suspicious');   // 只有剛註冊
  assert.equal(level('https://old-shop.top/', at(2000)), 'unknown');         // 只有後綴
});

test('「判斷錯了？」回報網址只帶網域與判斷原因', () => {
  const r = assessUrl('https://paypa1.com/signin?token=SECRET&email=a@b.c');
  const u = new URL(feedbackUrl(r, '0.3.0'));
  assert.equal(u.origin + u.pathname, 'https://github.com/casperch100/SiteGuard/issues/new');
  assert.equal(u.searchParams.get('template'), 'false-positive.yml');
  assert.equal(u.searchParams.get('domain'), 'paypa1.com');
  assert.equal(u.searchParams.get('level'), '可疑（Popup 或連結標示為可疑）');
  assert.equal(u.searchParams.get('version'), '0.3.0');
  assert.ok(u.searchParams.get('reasons').includes('PayPal'));
  assert.ok(!u.href.includes('SECRET') && !u.href.includes('signin') && !u.href.includes('email'), '不能帶入路徑或查詢參數');
  // 沒發現風險 → 回報漏抓，網域改成 [.]
  const m = new URL(feedbackUrl(assessUrl('https://new-coffee-shop.com/menu'), '0.3.0'));
  assert.equal(m.searchParams.get('template'), 'missed-scam.yml');
  assert.equal(m.searchParams.get('domain'), 'new-coffee-shop[.]com');
  assert.equal(defang('a.b.c'), 'a[.]b[.]c');
  // 可信任網站、165 名單、自己回報的網站、無法判斷的網址都不提供
  assert.equal(feedbackUrl(assessUrl('https://shopee.tw/')), null);
  assert.equal(feedbackUrl(assessUrl('https://myship-711-com-tw.cfd/', { blocklist: LIST })), null);
  assert.equal(feedbackUrl(assessUrl('https://x.com/', { reports: { 'x.com': { category: '假購物' } } })), null);
  assert.equal(feedbackUrl(assessUrl('javascript:alert(1)')), null);
});

test('以路徑區分使用者的共用服務：不沿用服務商的可信任判斷，回報只針對那一份內容', () => {
  for (const u of ['https://sites.google.com/view/esun-login', 'https://docs.google.com/forms/d/e/abc/viewform',
    'https://storage.googleapis.com/bucket/paypal-login.html', 'https://script.googleusercontent.com/macros/x']) {
    assert.ok(level(u) !== 'safe', u);
  }
  const t = parseTarget('https://docs.google.com/forms/d/e/abc/viewform');
  assert.equal(t.siteKey, 'docs.google.com/forms/d/e');
  assert.equal(parseTarget('https://sites.google.com/view/shop-a/home').siteKey, 'sites.google.com/view/shop-a');
  assert.equal(domainForAgeLookup('https://sites.google.com/view/shop-a'), null); // 年齡是服務本身的，不查
  const reports = { 'sites.google.com/view/shop-a': { category: '假購物' } };
  assert.equal(assessUrl('https://sites.google.com/view/shop-a/pay', { reports }).level, 'danger');
  assert.equal(assessUrl('https://sites.google.com/view/shop-b', { reports }).level, 'unknown');
  assert.equal(level('https://www.google.com/search?q=x'), 'safe'); // 一般的 Google 網站不受影響
});

test('開放註冊的國碼後綴，品牌同名也不算官方網站', () => {
  assert.equal(level('https://shopee.cc/'), 'suspicious');
  assert.equal(level('https://paypal.cc/'), 'danger');
  assert.ok(['suspicious', 'danger'].includes(level('https://netflix.tv/')));
  assert.ok(!['suspicious', 'danger'].includes(level('https://www.google.de/'))); // 真正的國家網域仍不誤判
  assert.ok(!['suspicious', 'danger'].includes(level('https://shopee.co.id/')));
  assert.ok(!['suspicious', 'danger'].includes(level('https://www.google.com.co/'))); // 國家二層網域
  assert.ok(!['suspicious', 'danger'].includes(level('https://apple.co/x'))); // Apple 自己的短網址
});

test('常見英文字不會被當成仿冒短品牌名稱', () => {
  for (const u of ['https://apply.com/', 'https://ample.com/']) assert.equal(level(u), 'unknown', u);
  assert.equal(level('https://paypa1.com/'), 'suspicious'); // 形近字仍抓得到
  assert.equal(level('https://app1e.com/'), 'suspicious');
});

test('更多二層公眾後綴', () => {
  assert.equal(parseTarget('https://www.lazada.com.my/').registrable, 'lazada.com.my');
  assert.equal(parseTarget('https://shop.example.co.id/').registrable, 'example.co.id');
  assert.equal(parseTarget('https://a.example.org.uk/').registrable, 'example.org.uk');
});

test('美國政府、學術、軍事網域視為可信任', () => {
  for (const u of ['https://www.irs.gov/', 'https://www.mit.edu/', 'https://www.army.mil/']) assert.equal(level(u), 'safe', u);
});

test('註冊日期在未來時不當成剛註冊', () => {
  const now = Date.parse('2026-11-27T12:00:00Z');
  assert.equal(ageInDays('2027-03-01', now), null);
  assert.equal(ageInDays('2026-11-27', now), 0);
});

test('回報網址不帶出網址中「@」前面的內容', () => {
  const r = assessUrl('https://account.SECRET123@paypa1.com/');
  assert.ok(r.reasons.some((x) => x.text.includes('SECRET123'))); // 本機顯示仍完整
  assert.ok(!feedbackUrl(r, '0.4.0').includes('SECRET123'));
  assert.equal(safeReasonText('網址用「@」偽裝成「www.bank.com」，實際會前往「x.com」'), '網址用「@」偽裝成另一個網域，實際會前往「x.com」');
});

test('CSV 標題列有雙引號也能解析', () => {
  const csv = '"民國年月","網域","網站性質","法律依據","聲請單位"\n11511,header-quoted.top,電子商務,條例,單位\n';
  assert.equal(mergeSuspendedCsv(csv, LIST, isAllowedHost).added, 1);
});

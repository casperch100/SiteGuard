import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessUrl, parseTarget, levenshtein } from '../src/lib/risk.js';

const level = (u, opts) => assessUrl(u, opts).level;

test('白名單與政府網站判定為安全', () => {
  for (const u of ['https://shopee.tw/', 'https://www.cathaybk.com.tw/x', 'https://www.post.gov.tw/', 'google.com', 'https://mail.google.com/']) {
    assert.equal(level(u), 'safe', u);
  }
});

test('黑名單網站判定為危險並帶分類', () => {
  const r = assessUrl('https://shopee-tw-sale.top/flash');
  assert.equal(r.level, 'danger');
  assert.equal(r.category, '假購物');
  assert.equal(level('sub.gold-invest-vip.xyz'), 'danger');
});

test('仿冒網址由規則判定為危險', () => {
  for (const u of ['https://paypa1.com/signin', 'https://line-login-secure.com/', 'https://esunbank-tw.online/']) {
    assert.equal(level(u), 'danger', u);
  }
});

test('可疑但未達危險', () => {
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
  const r = assessUrl('https://www.new-coffee-shop.com/', { reports });
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

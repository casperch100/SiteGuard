#!/usr/bin/env node
// 執行離線評估，輸出 eval/REPORT.md，並在 eval/history.csv 記錄當天結果。
//
//   node tools/eval/evaluate.mjs [--window 28]
//
// 需要先執行：
//   ruby -Ku tools/eval/collect_positives.rb   # 收集詐騙網域
//   ruby -Ku tools/eval/build_negatives.rb     # 產生正常網域清單
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseList } from '../../src/lib/blocklist.js';
import { evaluateAll, parseCsv, toMarkdown, historyRow, HISTORY_HEADER } from './metrics.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../..');
const read = (p) => readFileSync(join(ROOT, p), 'utf8');
const arg = (name, def) => {
  const i = process.argv.indexOf(name);
  return i === -1 ? def : process.argv[i + 1];
};

const positives = parseCsv(read('eval/data/positives.csv'));
const negatives = read('eval/cache/negatives.txt').split('\n').filter(Boolean);
const blocklist = parseList(read('src/data/165-blocklist.txt'), JSON.parse(read('src/data/165-meta.json')));
const windowDays = Number(arg('--window', 28));
const agesPath = join(ROOT, 'eval/cache/negatives_age.json');
const negativeAges = existsSync(agesPath) ? JSON.parse(readFileSync(agesPath, 'utf8')) : null;

const results = evaluateAll({ positives, negatives, blocklist, windowDays, negativeAges });

const logPath = join(ROOT, 'eval/data/collect-log.csv');
const collectLog = existsSync(logPath) ? readFileSync(logPath, 'utf8') : '';
writeFileSync(join(ROOT, 'eval/REPORT.md'), toMarkdown(results, { collectLog }));

const histPath = join(ROOT, 'eval/history.csv');
const today = results[0].generatedAt.slice(0, 10);
const lines = existsSync(histPath) ? readFileSync(histPath, 'utf8').split('\n').filter(Boolean) : [HISTORY_HEADER];
const kept = lines.filter((l, i) => i === 0 || !l.startsWith(today + ',')); // 同一天重跑就覆蓋
kept.push(historyRow(results));
writeFileSync(histPath, kept.join('\n') + '\n');

const [rules, withList] = results;
console.log(`偵測率（只用規則）：${(rules.detection.rate * 100).toFixed(1)}%（${rules.detection.hit}/${rules.detection.n}）`);
console.log(`偵測率（加上 165）：${(withList.detection.rate * 100).toFixed(1)}%`);
console.log(`誤判率：${(rules.falsePositive.rate * 100).toFixed(2)}%（${rules.falsePositive.hit}/${rules.falsePositive.n}）`);

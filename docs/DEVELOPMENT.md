# 開發文件

這份文件寫給想修改、測試或打包 SiteGuard 的開發者。使用說明請看 [README](../README.md)，發展計畫請看 [ROADMAP](../ROADMAP.md)。

## 開發環境

- Google Chrome 114 以上
- Ruby（macOS 內建的 2.6 即可）：資料轉換、評估、打包工具
- Node.js 20 以上（選用）：沒有的話，測試與評估可以改用瀏覽器或無頭 Chrome 執行

## 在本機載入擴充功能

1. 在 Chrome 開啟 `chrome://extensions`。
2. 開啟右上角的「**開發人員模式**」。
3. 按「**載入未封裝項目**」，選擇這個專案資料夾。
4. 修改程式後，在 `chrome://extensions` 按 SiteGuard 卡片上的重新載入按鈕。

## 判斷方式（`src/lib/risk.js`）

依序判斷，命中就停止：

1. **使用者自己回報過** → 危險（100 分）
2. 在 **165 涉詐網站名單**中（含子網域）→ 危險（100 分）
3. 在**白名單**中，或是 `.gov.tw`、`.edu.tw` 網域 → 可信任
4. **啟發式規則**分數加總：70 分以上為危險，35 分以上為可疑

| 規則 | 分數 |
|---|---|
| 網域註冊 30 天內／3 個月內／半年內（RDAP，見下方「網域年齡」） | 40／30／15 |
| 形近字或錯字仿冒官方網域（`paypa1.com`） | 50 |
| 和官方網站同名但後綴不同（`shopee.top`） | 45 |
| 用「@」偽裝網址（`www.bank.com@evil.com`） | 45 |
| 網址含有品牌名稱，但不是官方網站（`line-login-xxx.com`） | 40 |
| Punycode（國際化字元）網域 | 40 |
| 直接使用 IP 位址，而不是網域名稱 | 30 |
| 詐騙網站常用的網域後綴（`.top`、`.xyz`、`.vip` 等） | 15 |
| 可疑字詞（login、verify、invest 等） | 每個 10，最多 20 |
| 未使用 HTTPS、連字號過多、子網域層數過多、主機名稱過長 | 各 10 |

規則用到的白名單、品牌清單、可疑後綴與字詞都在 `src/data/rules.js`。

## 網域年齡（RDAP）

- **查詢對象**：直接查該頂級網域的註冊管理機構。對照表來自 IANA，內建在 `src/data/rdap-bootstrap.json`，由 `tools/update_rdap_bootstrap.rb` 產生。
- **只送出可註冊網域**（`src/lib/risk.js` 的 `domainForAgeLookup`）。白名單、政府網站、IP、本機網址、165 名單上的網站都不查。
- **什麼時候查**（`src/background.js`）：
  - 導航到沒查過的網站時：先放行，背景查詢；查到結果後如果變成「危險」，而且分頁還停在同一個網域，才補上警告頁。
  - Popup、警告頁主動查詢時（訊息帶 `lookup: true`）。
  - 網頁連結標記與滑過提示**不查**，只用已快取的結果，避免把頁面上每個連結的網域都送出去。
- **快取**：`chrome.storage.local` 的 `domainAges`，查到的保存 30 天，查不到的 1 天後重試，最多 3,000 筆。
- **設定**：`chrome.storage.local` 的 `settings.domainAgeLookup`，預設開啟，可在設定頁（`src/options/`）關閉。

更新 RDAP 對照表：

```bash
ruby -Ku tools/update_rdap_bootstrap.rb
```

## 165 資料

| 資料集 | 用途 | 更新 |
|---|---|---|
| [165反詐騙諮詢專線_遭停止解析涉詐網站](https://data.gov.tw/dataset/176455) | 主要名單，以網站性質（金融保險、電子商務、運輸倉儲…）作為分類 | 官方每月更新；擴充功能每週檢查一次 |
| [165反詐騙諮詢專線_假投資(博弈)網站](https://data.gov.tw/dataset/160055) | 歷史資料（官方已停止更新，改由上面的資料集取代） | 只在內建快照中 |

- **內建快照**：`src/data/165-blocklist.txt`（每行「主機名稱<TAB>分類代碼」）與 `src/data/165-meta.json`，由 `tools/update_165.rb` 產生。
- **自動更新**：Service Worker 每週用 `chrome.alarms` 下載最新的「遭停止解析涉詐網站」CSV，合併後存在 `chrome.storage.local`。下載失敗時繼續使用目前的名單。
- **避免誤擋**：白名單上的網域（例如 `play.google.com`）即使出現在原始資料中也不列入。
- **授權**：政府資料開放授權條款第 1 版。Popup、隱私權政策與商店說明中都標示了資料來源。

更新內建快照：

```bash
ruby -Ku tools/update_165.rb
```

## Demo 測試頁

擴充功能只在 `http://` 與 `https://` 網頁上運作，所以測試頁要透過本機伺服器開啟：

```bash
ruby -run -e httpd . -p 8765
```

然後前往 http://localhost:8765/demo/index.html。「165 名單」區塊的網域都已遭停止解析，點了只會看到 SiteGuard 的警告頁。

## 測試

- **有 Node.js**：`node --test test/`
- **沒有 Node.js**：先啟動上面的伺服器，再開啟 http://localhost:8765/test/browser.html。執行的是同一份 `test/risk.test.js`，並會用真正的 165 快照測試載入速度，以及白名單網站是否被誤列。

## 偵測評估

用和擴充功能同一份偵測引擎，離線計算「新詐騙網站偵測率」與「正常網站誤判率」。目標與進度見 [ROADMAP](../ROADMAP.md)，最新結果見 [eval/REPORT.md](../eval/REPORT.md)，每日趨勢見 `eval/history.csv`。

GitHub Actions 每天台灣時間 09:30 自動執行（`.github/workflows/eval.yml`）；`tools/eval/`、`src/lib/` 或 `src/data/rules.js` 有變更並推送到 `main` 時也會重跑。本機手動執行：

```bash
ruby -Ku tools/eval/collect_positives.rb     # 收集 PhishTank 仍在線的釣魚網域（加 --165 download 一併收集 165 新增網域）
ruby -Ku tools/eval/build_negatives.rb       # 下載 Tranco 熱門網站排行，產生正常網域清單
ruby -Ku tools/eval/run_local.rb             # 沒有 Node.js 時用無頭 Chrome 執行評估（有 Node.js 可改用 node tools/eval/evaluate.mjs）
```

| 評估資料來源 | 用途 | 使用條件 |
|---|---|---|
| [PhishTank](https://phishtank.org/)（Cisco Talos） | 仍在線的釣魚網域 | 商業與非商業用途皆可 |
| 165 遭停止解析涉詐網站 | 台灣在地樣本 | 政府資料開放授權條款第 1 版 |
| [Tranco](https://tranco-list.eu/) | 正常網域 | 部分來源為 CC BY-NC／CC BY-SA，只在評估時下載，不放進 repo |

## 打包上架

```bash
ruby -Ku tools/update_165.rb && ruby -Ku tools/update_rdap_bootstrap.rb && sh tools/pack.sh
```

產生 `dist/site-guard-<版本>.zip`，只包含 `manifest.json`、`icons/`、`src/`。送審步驟見 [store/SUBMIT.md](../store/SUBMIT.md)。

改版時記得：
1. 修改 `manifest.json` 的 `version`。
2. 在 [CHANGELOG](../CHANGELOG.md) 記錄這次的變更。
3. 如果改到資料處理方式，同步更新隱私權政策 `docs/index.html`。

## 專案結構

```
manifest.json              MV3 設定
src/background.js          Service Worker：攔截、badge、右鍵選單、165 名單載入與每週更新
src/lib/risk.js            風險判斷引擎（純函式，和測試、評估共用）
src/lib/blocklist.js       165 名單的解析、查詢、CSV 合併（純函式）
src/lib/rdap.js            網域註冊日期：查詢網址、解析回應、快取期限（純函式）
src/data/rules.js          白名單、品牌清單、可疑後綴與字詞
src/data/165-blocklist.txt 165 名單內建快照
src/data/165-meta.json     165 名單的分類、資料月份、來源
src/data/rdap-bootstrap.json  各頂級網域的 RDAP 伺服器（來自 IANA）
src/options/               設定頁
src/popup/                 工具列 Popup（也用作右鍵檢查的視窗）
src/warning/               危險網站警告頁
src/content/               網頁上的連結標記與滑過提示
icons/                     擴充功能圖示（由 tools/make_icons.rb 產生）
docs/index.html            隱私權政策（GitHub Pages 發布）
docs/DEVELOPMENT.md        本文件
demo/index.html            Demo 測試頁
test/                      引擎測試
eval/                      評估資料、報告、每日趨勢
tools/update_165.rb        下載 165 公開資料並產生內建快照
tools/update_rdap_bootstrap.rb  下載 IANA 的 RDAP 對照表
tools/pack.sh              打包上架用的 zip（輸出到 dist/）
tools/eval/                評估工具
store/                     上架資料：商店文案、截圖、送審步驟
.github/                   GitHub Actions 與 Issue 範本
```

## 已知的技術限制

- **網域解析**：目前用簡化的公眾後綴表，之後可改用完整的 Public Suffix List。
- **攔截方式**：目前在 `webNavigation.onBeforeNavigate` 時導向警告頁；改用 `declarativeNetRequest` 規則可以更早攔截。
- **回報**：只存在使用者自己的電腦。如果要分享給其他使用者，需要後端、防灌票機制與人工審核。

# SiteGuard 網站安全檢查（Chrome 擴充功能）

開網站之前先告訴你，這個網站可能是詐騙、仿冒，或其他可疑網站。
所有判斷都在瀏覽器裡完成，沒有後端，也不會上傳任何使用者資料。

詐騙網站名單來自**內政部警政署 165 反詐騙諮詢專線**的公開資料（超過 12 萬個網域），擴充功能每週自動更新。

## 功能

| 功能 | 說明 |
|---|---|
| 攔截危險網站 | 前往危險網站時先導向警告頁；使用者可以選擇「仍要前往」，本次瀏覽期間就不再攔截該網域 |
| 工具列 badge | `✓` 可信任、`?` 可疑、`!` 危險；沒有標示代表未發現明顯風險 |
| Popup | 顯示目前網站的風險分數與原因，也可以查詢其他網址、回報網站；底部顯示 165 名單的資料月份與筆數 |
| 連結標記 | 頁面上的危險連結加紅框，可疑連結加橘色虛線框；之後才載入的內容（例如聊天訊息）也會掃描 |
| 滑過提示 | 滑鼠移到連結上，會顯示風險等級與原因 |
| 右鍵檢查 | 對連結或反白的文字按右鍵，選「用 SiteGuard 檢查」 |

## 判斷方式（`src/lib/risk.js`）

1. **自己回報過** → 危險（100 分）
2. 在 **165 涉詐網站名單**中（含子網域）→ 危險（100 分）
3. 在**白名單**中，或是 `.gov.tw`、`.edu.tw` 網域 → 可信任
4. **啟發式規則**分數加總：70 分以上為危險，35 分以上為可疑

| 規則 | 分數 |
|---|---|
| 形近字或錯字仿冒官方網域（`paypa1.com`） | 50 |
| 和官方網站同名但後綴不同（`shopee.top`） | 45 |
| 用「@」偽裝網址（`www.bank.com@evil.com`） | 45 |
| 網址含有品牌名稱，但不是官方網站（`line-login-xxx.com`） | 40 |
| Punycode（國際化字元）網域 | 40 |
| 直接使用 IP 位址，而不是網域名稱 | 30 |
| 詐騙網站常用的網域後綴（`.top`、`.xyz`、`.vip` 等） | 15 |
| 可疑字詞（login、verify、invest 等） | 每個 10，最多 20 |
| 未使用 HTTPS、連字號過多、子網域層數過多、主機名稱過長 | 各 10 |

## 165 資料

| 資料集 | 用途 | 更新 |
|---|---|---|
| [165反詐騙諮詢專線_遭停止解析涉詐網站](https://data.gov.tw/dataset/176455) | 主要名單，網站性質（金融保險、電子商務、運輸倉儲…）作為分類 | 每月；擴充功能每週檢查一次 |
| [165反詐騙諮詢專線_假投資(博弈)網站](https://data.gov.tw/dataset/160055) | 歷史資料（官方已停止更新，改由上面的資料集取代） | 只在內建快照中 |

- **內建快照**：`src/data/165-blocklist.txt`（每行「主機名稱<TAB>分類代碼」）與 `src/data/165-meta.json`，由 `tools/update_165.rb` 產生。
- **自動更新**：Service Worker 每週用 `chrome.alarms` 下載最新的「遭停止解析涉詐網站」CSV，合併後存在 `chrome.storage.local`。下載失敗時繼續使用目前名單。
- **避免誤擋**：白名單上的網域（例如 `play.google.com`）即使出現在原始資料中也不列入。
- **授權**：政府資料開放授權條款第 1 版，Popup 與商店說明中標示資料來源。

更新內建快照：

```bash
ruby -Ku tools/update_165.rb
```

## 安裝（開發者模式）

1. 在 Chrome 開啟 `chrome://extensions`。
2. 開啟右上角的「**開發人員模式**」。
3. 按「**載入未封裝項目**」，選擇這個 `site-guard` 資料夾。

## 試玩 Demo

擴充功能只在 `http://` 與 `https://` 網頁上運作，所以測試頁要透過本機伺服器開啟：

```bash
ruby -run -e httpd . -p 8765
```

然後前往 http://localhost:8765/demo/index.html。測試頁上的危險連結取自 165 名單，而且都已遭停止解析，點了只會看到 SiteGuard 的警告頁。

## 測試

- 有 Node.js：`node --test test/`
- 沒有 Node.js：先啟動上面的伺服器，再開啟 http://localhost:8765/test/browser.html（執行的是同一份 `test/risk.test.js`，並用真正的 165 快照測試載入速度與白名單是否被誤列）。

## 專案結構

```
manifest.json              MV3 設定
src/background.js          Service Worker：攔截、badge、右鍵選單、165 名單載入與每週更新
src/lib/risk.js            風險判斷引擎（純函式，和測試共用）
src/lib/blocklist.js       165 名單的解析、查詢、CSV 合併（純函式）
src/data/rules.js          白名單、品牌清單、可疑後綴與字詞
src/data/165-blocklist.txt 165 名單內建快照
src/data/165-meta.json     165 名單的分類、資料月份、來源
src/popup/                 工具列 Popup（也用作右鍵檢查的視窗）
src/warning/               危險網站警告頁
src/content/               網頁上的連結標記與滑過提示
demo/index.html            Demo 測試頁
test/                      引擎測試
icons/                     擴充功能圖示（由 tools/make_icons.rb 產生）
tools/update_165.rb        下載 165 公開資料並產生內建快照
tools/pack.sh              打包上架用的 zip（輸出到 dist/）
store/                     上架資料：商店文案、隱私權政策、截圖、送審步驟
index.html                 GitHub Pages 用的隱私權政策（和 store/privacy-policy.html 相同）
```

## 上架

請看 [store/SUBMIT.md](store/SUBMIT.md)。

## 已知限制與之後可以做的

- **新詐騙網站**：165 名單是事後公告，剛出現的詐騙網站要靠啟發式規則辨識。
- **網域年齡**：可以用 RDAP 查詢真實註冊日期，作為額外的判斷依據。
- **網域解析**：改用完整的 Public Suffix List，取代目前簡化的後綴表。
- **攔截方式**：改用 `declarativeNetRequest` 規則，比目前的 `webNavigation` 導向更早攔截。
- **回報**：目前只存在這台電腦。如果要分享給其他使用者，需要後端、防灌票機制與人工審核。

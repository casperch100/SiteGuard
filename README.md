# SiteGuard 網站安全檢查（Chrome 擴充功能 POC）

瀏覽器版的 Whoscall：開網站之前先告訴你，這個網站可能是詐騙、仿冒，或其他可疑網站。
這個 POC 完全在瀏覽器裡執行，使用模擬資料，沒有後端，也不會上傳任何資料。

## 功能

| 功能 | 說明 |
|---|---|
| 攔截危險網站 | 前往危險網站時先導向警告頁；使用者可以選擇「仍要前往」，本次瀏覽期間就不再攔截該網域 |
| 工具列 badge | `✓` 可信任、`?` 可疑、`!` 危險；沒有標示代表未發現明顯風險 |
| Popup | 顯示目前網站的風險分數與原因，也可以查詢其他網址、回報網站 |
| 連結標記 | 頁面上的危險連結加紅框，可疑連結加橘色虛線框；之後才載入的內容（例如聊天訊息）也會掃描 |
| 滑過提示 | 滑鼠移到連結上，會顯示風險等級與原因 |
| 右鍵檢查 | 對連結或反白的文字按右鍵，選「用 SiteGuard 檢查」 |

## 判斷方式（`src/lib/risk.js`）

1. **自己回報過**或在**黑名單**中（模擬 165 資料）→ 危險（100 分）
2. 在**白名單**中，或是 `.gov.tw`、`.edu.tw` 網域 → 可信任
3. **啟發式規則**分數加總：70 分以上為危險，35 分以上為可疑

| 規則 | 分數 |
|---|---|
| 形近字或錯字仿冒官方網域（`paypa1.com`） | 50 |
| 和官方網站同名但後綴不同（`shopee.top`） | 45 |
| 用「@」偽裝網址（`www.bank.com@evil.com`） | 45 |
| 網址含有品牌名稱，但不是官方網站（`line-login-xxx.com`） | 40 |
| Punycode（國際化字元）網域 | 40 |
| 網域註冊未滿 30 天／7 天（模擬資料） | 30／35 |
| 直接使用 IP 位址，而不是網域名稱 | 30 |
| 詐騙網站常用的網域後綴（`.top`、`.xyz`、`.vip` 等） | 15 |
| 可疑字詞（login、verify、invest 等） | 每個 10，最多 20 |
| 未使用 HTTPS、連字號過多、子網域層數過多、主機名稱過長 | 各 10 |

## 安裝（開發者模式）

1. 在 Chrome 開啟 `chrome://extensions`。
2. 開啟右上角的「**開發人員模式**」。
3. 按「**載入未封裝項目**」，選擇這個 `site-guard` 資料夾。
4. （選用）在擴充功能的詳細資料頁開啟「**允許存取檔案網址**」，就能直接用檔案方式開啟測試頁。

## 試玩 Demo

開啟 `demo/index.html`。可以直接用檔案方式開啟（需要上面的第 4 步），或透過本機伺服器：

```bash
ruby -run -e httpd . -p 8765
```

然後前往 http://localhost:8765/demo/index.html。測試頁上的網址都是虛構的，點危險連結會被導向警告頁。

## 測試

- 有 Node.js：`node --test test/`
- 沒有 Node.js：先啟動上面的伺服器，再開啟 http://localhost:8765/test/browser.html（執行的是同一份 `test/risk.test.js`）。

## 專案結構

```
manifest.json            MV3 設定
src/background.js        Service Worker：攔截、badge、右鍵選單、訊息處理
src/lib/risk.js          風險判斷引擎（純函式，和測試共用）
src/data/mock-data.js    模擬的黑名單、白名單、品牌清單、網域年齡
src/popup/               工具列 Popup（也用作右鍵檢查的視窗）
src/warning/             危險網站警告頁
src/content/             網頁上的連結標記與滑過提示
demo/index.html          Demo 測試頁
test/                    引擎測試
icons/                   擴充功能圖示（由 tools/make_icons.rb 產生）
tools/pack.sh            打包上架用的 zip（輸出到 dist/）
store/                   上架資料：商店文案、隱私權政策、截圖、送審步驟
```

## 上架

請看 [store/SUBMIT.md](store/SUBMIT.md)。

## 已知限制與正式版的下一步

- **資料**：把模擬資料換成 165 公開資料與威脅情資，每日下載，存在 IndexedDB 或 Bloom filter。
- **網域年齡**：改用 RDAP 查詢真實註冊日期。這需要後端或支援 CORS 的 RDAP 服務，而且只送網域。
- **網域解析**：改用完整的 Public Suffix List，取代目前簡化的後綴表。
- **攔截方式**：改用 `declarativeNetRequest` 規則，比目前的 `webNavigation` 導向更早攔截、效能更好。
- **回報**：目前只存在這台電腦。正式版需要後端、防灌票機制與人工審核。
- **隱私**：如果加上後端查詢，採用 k-匿名做法（只送網域雜湊值的前綴）。

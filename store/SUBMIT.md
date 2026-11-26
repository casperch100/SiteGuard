# 上架 Chrome 線上應用程式商店：步驟與檢查清單

## 已備妥的東西

| 項目 | 檔案 |
|---|---|
| 上傳用 zip | `dist/site-guard-0.1.0.zip`（用 `sh tools/pack.sh` 重新產生） |
| 商店圖示 128×128 | `icons/icon128.png` |
| 螢幕截圖 1280×800 ×3 | `store/screenshots/screenshot-1.jpg`～`screenshot-3.jpg` |
| 小型宣傳圖塊 440×280 | `store/screenshots/promo-small.jpg` |
| 商店文案、權限理由、隱私權欄位 | `store/listing.md` |
| 隱私權政策 | `store/privacy-policy.html`（需要放到公開網址） |

## 送審前一定要處理的事

### 1. 決定公開範圍：建議先選「不公開」（Unlisted）
目前的黑名單和網域年齡都是**模擬資料**，而判斷原因會顯示「模擬 165 資料」等字樣。如果直接「公開」給一般大眾：
- 真實的詐騙網站幾乎都不在名單裡，使用者可能誤以為「沒警告就是安全」。
- 審查人員看到「模擬資料」，可能以「功能誤導」為由退件。

建議第一版先選「**不公開**」，給內部同事或小範圍使用者試用；接上真實資料（例如 165 公開資料）後，再改成「公開」。

### 2. 把隱私權政策放到公開網址
商店要求填寫一個任何人都能開啟的隱私權政策網址。任選一種方式：
- **GitHub Pages**：建一個公開 repo，放入 `privacy-policy.html`，在 Settings → Pages 啟用。
- **Google 協作平台（Google Sites）**：新增頁面，把內容貼上後發布。
- 公司官網上的任一頁面。

聯絡方式使用 GitHub Issues：頁面放在 `https://<帳號>.github.io/<repo>/` 時，會自動連到 `https://github.com/<帳號>/<repo>/issues`。要上傳的檔案是 `store/github-pages/index.html`。

### 3. 確認名稱可以用
「SiteGuard」這個名字市面上已經有其他資安產品在用。正式公開前，建議先查商標，必要時換名稱。要改的地方：`manifest.json` 的 `name`、`short_name`、`action.default_title`，以及 `store/` 裡的文案和截圖（改完 `compose.html` 再重新截圖）。

### 4. 以公司名義上架前，先確認內部流程
如果要用公司名義或公司帳號上架，可能需要法務、資安或品牌部門的審核。

## 上架步驟

1. **註冊開發人員帳號**
   前往 https://chrome.google.com/webstore/devconsole ，用 Google 帳號登入，支付一次性 5 美元註冊費，並驗證聯絡用電子郵件。帳號需要開啟兩步驟驗證。
   > 如果要以公司名義上架，建議用公司的 Google 帳號，或建立「群組發布者」（Group publisher）。
2. **上傳套件**：按「新增項目」，上傳 `dist/site-guard-0.1.0.zip`。
3. **填寫「商店資訊」**：照 `store/listing.md` 第一節貼上，並上傳圖示、截圖和宣傳圖塊。
4. **填寫「隱私權」**：照 `store/listing.md` 第二節填寫單一用途、各權限理由、遠端程式碼和資料使用，再填入隱私權政策網址。
5. **填寫「發布」**：公開範圍選「不公開」，地區和價格照 `listing.md` 第三節。
6. **送審**：按「提交審查」。因為要求在所有網站上運作（`<all_urls>`），審查可能較久，通常需要幾天到幾週。

## 之後更新版本
1. 修改 `manifest.json` 的 `version`（例如 `0.1.1`）。
2. 執行 `sh tools/pack.sh` 產生新的 zip。
3. 在開發人員資訊主頁的「套件」頁上傳新 zip，再提交審查。

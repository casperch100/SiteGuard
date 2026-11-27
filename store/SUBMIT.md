# 上架 Chrome 線上應用程式商店：步驟與檢查清單

## 已備妥的東西

| 項目 | 檔案 |
|---|---|
| 上傳用 zip | `dist/site-guard-<版本>.zip`（用 `sh tools/pack.sh` 重新產生） |
| 商店圖示 128×128 | `icons/icon128.png` |
| 螢幕截圖 1280×800 ×3 | `store/screenshots/screenshot-1.jpg`～`screenshot-3.jpg` |
| 小型宣傳圖塊 440×280 | `store/screenshots/promo-small.jpg` |
| 商店文案、權限理由、隱私權欄位 | `store/listing.md` |
| 隱私權政策 | https://casperch100.github.io/SiteGuard/ （原始檔 `docs/index.html`） |

## 送審前一定要處理的事

### 1. 補上需要你提供的資訊
- ~~**發布者名稱**~~：已填入隱私權政策（casperch100）。
- **開發人員聯絡信箱**：在商店後台的「帳戶」頁面填寫並驗證（不要寫進這個公開 repo）。
- **交易者身分聲明**：選「**非交易者**」（個人、免費、非商業發布）。之後若改用公司名義或開始有收入，要改成「交易者」並提供地址和電話。

### 2. 更新 165 名單快照（每次送審前）
名單每週會在使用者端自動更新，但內建快照越新，剛安裝時的保護越完整：

```bash
ruby -Ku tools/update_165.rb && ruby -Ku tools/update_rdap_bootstrap.rb && sh tools/pack.sh
```

### 3. 隱私權政策有改動時，同步到 GitHub Pages
修改 `docs/index.html` 並推送，GitHub Pages 會自動更新。

### 4. 確認名稱可以用
「SiteGuard」這個名字市面上已經有其他資安產品在用。正式公開前，建議先查商標，必要時換名稱。要改的地方：`manifest.json` 的 `name`、`short_name`、`action.default_title`，以及 `store/` 裡的文案和截圖（改完 `compose.html` 再重新截圖）。

### 5. 以公司名義上架前，先確認內部流程
如果要用公司名義或公司帳號上架，可能需要法務、資安或品牌部門的審核。

## 上架步驟

1. **註冊開發人員帳號**
   前往 https://chrome.google.com/webstore/devconsole ，用 Google 帳號登入，支付一次性 5 美元註冊費，並驗證聯絡用電子郵件。帳號需要開啟兩步驟驗證。
   > 如果要以公司名義上架，建議用公司的 Google 帳號，或建立「群組發布者」（Group publisher）。
2. **上傳套件**：按「新增項目」，上傳 `dist/site-guard-<版本>.zip`（版本號以 `manifest.json` 的 `version` 為準）。
3. **填寫「商店資訊」**：照 `store/listing.md` 第一節貼上，並上傳圖示、截圖和宣傳圖塊。
4. **填寫「隱私權」**：照 `store/listing.md` 第二節填寫單一用途、各權限理由、遠端程式碼和資料使用，再填入隱私權政策網址。
5. **填寫「發布」**：公開範圍、地區和價格照 `listing.md` 第三節。
6. **送審**：按「提交審查」。因為要求在所有網站上運作（`<all_urls>`），審查可能較久，通常需要幾天到幾週。

## 之後更新版本
1. 修改 `manifest.json` 的 `version`（例如 `0.4.0` → `0.4.1`）。
2. 執行 `ruby -Ku tools/update_165.rb && ruby -Ku tools/update_rdap_bootstrap.rb && sh tools/pack.sh`，更新 165 名單與 RDAP 對照表，並產生新的 zip。
3. 在開發人員資訊主頁的「套件」頁上傳新 zip，再提交審查。

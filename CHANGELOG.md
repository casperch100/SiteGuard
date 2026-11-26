# 版本變更紀錄

格式參考 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)，版本號依照[語意化版本](https://semver.org/lang/zh-TW/)。

## [未發布]

### 新增
- 離線偵測評估機制：每天收集仍在線的詐騙網域，計算新詐騙網站偵測率與正常網站誤判率（GitHub Actions 自動執行，報告見 `eval/REPORT.md`）。
- 發展計畫 [ROADMAP](ROADMAP.md)、開發文件 [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)、Issue 回報範本、[安全性政策](SECURITY.md)。
- 以 MIT 授權條款釋出程式碼。

### 變更
- README 改寫為給使用者看的說明，開發相關內容移到 `docs/DEVELOPMENT.md`。
- 隱私權政策移到 `docs/index.html`。

## [0.2.0] - 2026-11-26

### 新增
- 改用**內政部警政署 165 反詐騙諮詢專線公開資料**作為詐騙網站名單：內建 126,212 個網域（遭停止解析涉詐網站、假投資(博弈)網站）。
- 每週自動從政府資料開放平臺下載最新的「遭停止解析涉詐網站」名單；下載失敗時繼續使用目前的名單。
- Popup 顯示名單的資料月份、筆數與資料來源。
- 名單比對包含子網域；共用平台（例如 `workers.dev`）只比對名單上的特定子網域，不會連累其他網站。

### 變更
- 判斷原因改為顯示 165 名單的分類與資料月份，例如「已列入 165 反詐騙公告名單：涉詐網站（運輸倉儲）」。
- 新增 `alarms` 權限（排程每週更新），最低 Chrome 版本改為 114。
- 隱私權政策新增「對外連線」與「資料來源」，並寫明發布者。

### 移除
- 移除所有模擬資料，包含模擬的詐騙網站名單與模擬的網域註冊天數規則。

## [0.1.0] - 2026-11-26

### 新增
- 第一個版本（POC）：攔截危險網站並顯示警告頁、工具列安全狀態、Popup 查詢與回報、網頁連結標記與滑過提示、右鍵檢查。
- 啟發式規則：形近字仿冒、同名不同後綴、品牌名稱、「@」偽裝網址、IP 位址、可疑網域後綴與字詞等。

[未發布]: https://github.com/casperch100/SiteGuard/compare/6aca90b...HEAD
[0.2.0]: https://github.com/casperch100/SiteGuard/commit/3105cea
[0.1.0]: https://github.com/casperch100/SiteGuard/commit/fcbd912

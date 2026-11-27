# 設計：用 declarativeNetRequest 在連線前攔截名單網站

> 狀態：提案（尚未實作）　對應版本：0.4.0　最後更新：2026-11-27

## 1. 為什麼要改

目前所有攔截都在 `webNavigation.onBeforeNavigate` 裡做：Service Worker 收到事件 → 判斷風險 → `chrome.tabs.update()` 導向警告頁。

這個做法有三個問題：

1. **擋得太晚。** `onBeforeNavigate` 是非同步事件，Service Worker 判斷完、再叫分頁換網址時，瀏覽器通常已經送出請求，甚至開始顯示詐騙網頁。對方伺服器看得到這次連線（IP、User-Agent、Referer），網頁可能已經跑了一小段腳本。
2. **Service Worker 睡著時更慢。** MV3 的 Service Worker 閒置約 30 秒就會被回收，下次導航要先喚醒、重新載入 12 萬筆名單（約 2.4 MB），第一次攔截可能慢上幾百毫秒。
3. **不是真的「擋下」。** 目前算是「事後把分頁拉走」，和商店說明、README 寫的「開網站前先幫你看一眼」有落差。

`declarativeNetRequest`（以下簡稱 DNR）的規則由瀏覽器在**送出請求之前**比對，不需要喚醒 Service Worker，符合「連線前攔截」的承諾。

## 2. 範圍

| 判斷來源 | 是否改用 DNR | 原因 |
|---|---|---|
| 165 名單（內建快照＋每週更新） | ✅ 改 | 固定網域清單，正好是 DNR 擅長的 |
| 使用者自己的回報 | ✅ 改 | 同上，網域清單 |
| 「仍要前往」放行 | ✅ 改 | 用優先權較高的 allow 規則 |
| 規則判斷（品牌仿冒、可疑後綴⋯⋯） | ❌ 不改 | 需要計分、形近字比對，DNR 規則表達不了 |
| 網域年齡（RDAP） | ❌ 不改 | 需要對外查詢，本來就只能事後補警告 |

也就是說，**名單命中＝硬攔截（DNR）；規則與網域年齡＝軟攔截（維持現狀）**。軟攔截的部分維持現在的行為與文案，不宣稱「連線前」。

不在範圍內：子框架（iframe）與子資源的攔截、規則判斷搬進 DNR、改變名單資料來源。

## 3. 設計

### 3.1 規則配置

全部使用**動態規則**（`updateDynamicRules`），在安裝、啟動、名單更新時由 Service Worker 重建。

| 規則 ID | 種類 | 優先權 | 條件 | 動作 |
|---|---|---|---|---|
| 1001–1099 | 動態 | 1 | `requestDomains`：165 名單（每條規則一段，例如 5 萬個網域） | redirect 到警告頁 |
| 2001 | 動態 | 1 | `requestDomains`：使用者回報的網域 | redirect 到警告頁 |
| 3001 起 | 工作階段（session） | 2 | `requestDomains`：使用者選擇放行的網域 | allow |

共通條件：`resourceTypes: ['main_frame']`；`regexFilter: '^(https?://.*)$'`（給轉址替換用）。

**為什麼用 `requestDomains`：** 一條規則可以帶一整串網域，而且會自動比對子網域。這和目前 `lookupHost()` 的行為一樣（名單上有 `evil.com`，`a.evil.com` 也算命中；共用平台只比對名單上那個子網域）。12 萬個網域只需要幾條規則，遠低於規則數上限。

**為什麼用動態規則而不是靜態規則檔：**
- 轉址要帶上原始網址，就得把警告頁的完整網址（含擴充功能 ID）寫進 `regexSubstitution`。靜態規則檔是打包時寫死的，開發版（未封裝）和商店版的 ID 不同；動態規則可以在執行時用 `chrome.runtime.getURL()` 產生。
- 每週更新名單時本來就要改規則，全部用動態規則只需要一套流程。
- 代價：Service Worker 第一次啟動時要建立規則（見 5.「需要先驗證」）。

### 3.2 轉址到警告頁

```js
action: {
  type: 'redirect',
  redirect: { regexSubstitution: chrome.runtime.getURL('src/warning/warning.html') + '#url=\\1' },
}
```

- 原始網址放在 `#` 後面，而不是 `?url=`：`regexSubstitution` 不會幫網址編碼，原始網址裡的 `&`、`?` 會把查詢字串弄亂。網路請求的網址本身不含 `#`，放在 hash 裡可以完整保留。
- 警告頁讀取網址的順序：`?url=`（現有軟攔截用，已編碼）→ `#url=`（DNR 用，未編碼，取 `#url=` 之後的全部字元）。兩種都要經過現有的 `safeTarget()`，只接受 http／https。

**備案（如果 `regexSubstitution` 轉到擴充功能頁面行不通）：** 改用 `redirect: { extensionPath: '/src/warning/warning.html' }`。原始網址由 `onBeforeNavigate` 記到 `chrome.storage.session`（以 tabId 為 key），警告頁載入後向背景詢問「這個分頁剛剛被擋的網址」。缺點是有時序問題，警告頁可能要等幾百毫秒。

### 3.3 警告頁變成「網頁可存取的資源」

DNR 把網頁請求轉到擴充功能頁面，該頁面必須列在 `web_accessible_resources`：

```json
"web_accessible_resources": [{
  "resources": ["src/warning/warning.html", "src/warning/warning.css", "src/warning/warning.js"],
  "matches": ["<all_urls>"],
  "use_dynamic_url": true
}]
```

這會帶來兩個新風險，需要一起處理：

| 風險 | 對策 |
|---|---|
| 網站可以藉由載入 `chrome-extension://<id>/…` 偵測使用者裝了 SiteGuard（指紋追蹤） | `use_dynamic_url: true`：資源網址每個工作階段都不同，無法事先猜到 |
| 惡意網站用 iframe 嵌入警告頁，誘騙使用者按「仍要前往」（點擊劫持） | 警告頁偵測到自己被嵌入（`window.top !== window`）就不顯示按鈕；manifest 的 `content_security_policy.extension_pages` 加上 `frame-ancestors 'none'` |
| 網站直接開啟 `warning.html#url=…` 假造警告頁 | 影響有限：按「仍要前往」只會前往網址列上本來就能去的網址。放行仍要經過 3.4 的訊息來源檢查 |

上一輪已經加上的 `safeTarget()`（拒絕 `javascript:` 等網址）就是為這一步做準備。

### 3.4 放行（仍要前往）

1. 警告頁送 `bypass` 訊息（只接受擴充功能自己的頁面，已在 0.3.x 加上來源檢查）。
2. 背景新增一條 **session 規則**：`allow`、優先權 2、`requestDomains: [registrable]`。共用平台用子網域，和現在的 `bypass` 一致。
3. Session 規則在關閉瀏覽器時自動清除，和現在 `storage.session` 的放行期間一樣。
4. 同時保留 `storage.session` 的 `bypass` 清單，讓軟攔截（規則判斷）也知道已經放行。

### 3.5 使用者回報

`report` / `unreport` 時重建規則 2001（整條換掉，`removeRuleIds` 和 `addRules` 放在同一次 `updateDynamicRules` 呼叫，是原子操作）。回報清單是空的就不建這條規則（`requestDomains` 不能是空陣列）。

### 3.6 名單更新

- **安裝／更新擴充功能（`onInstalled`）與瀏覽器啟動（`onStartup`）：** 讀目前的名單（`storage.local` 的 `list165`，沒有就用內建快照），重建 1001–1099。
- **每週更新（`alarms`）：** 下載、合併後重建 1001–1099。
- **比對版本：** 把「目前規則對應的資料月份＋筆數」存在 `storage.local`（例如 `dnrVersion`），相同就跳過重建，避免每次 Service Worker 被喚醒都重做。
- **失敗時：** `updateDynamicRules` 失敗（例如超過限制）就記錄錯誤，並在 `onBeforeNavigate` 裡**繼續用現在的軟攔截處理名單網站**，不會變成完全沒保護。

### 3.7 `onBeforeNavigate` 的調整

DNR 生效後，名單與回報網站的請求根本不會發出，但 `onBeforeNavigate` 仍會收到事件（事件在轉址前觸發）。為了避免導向兩次：

- 結果來自 165 名單或使用者回報，而且 DNR 規則已啟用（`dnrVersion` 存在）→ 交給 DNR，不再呼叫 `tabs.update()`。
- 其他情況（規則判斷、網域年齡）照舊。

### 3.8 權限

使用 `declarativeNetRequestWithHostAccess`，**不要**用 `declarativeNetRequest`：

- 前者在已經有 `<all_urls>` 主機權限的前提下，**不會新增安裝警告**；後者會多一句「封鎖任何網頁上的內容」。
- 轉址本來就需要該網址的主機權限，我們已經有了。
- 因為還沒上架，現在加權限不會讓既有使用者的擴充功能被停用；上架後再加就會。**這是在 0.4.0（第一次上架前）做這件事的主要理由。**

商店說明 `store/listing.md` 要補上這個權限的用途說明。隱私權政策不用改：規則只在本機比對，不會傳送任何資料。

## 4. 要改的檔案

| 檔案 | 改動 |
|---|---|
| `manifest.json` | 加 `declarativeNetRequestWithHostAccess`、`web_accessible_resources`、`content_security_policy` |
| `src/lib/dnr.js`（新） | 純函式：網域清單 → 規則陣列（分段、ID 分配、轉址網址），可以寫單元測試 |
| `src/background.js` | 建立／重建規則、`dnrVersion`、放行改用 session 規則、`onBeforeNavigate` 略過已由 DNR 處理的網站 |
| `src/warning/warning.js` | 支援 `#url=`、偵測被嵌入、修正「返回」按鈕（見下） |
| `test/risk.test.js` | `dnr.js` 的單元測試（分段、空清單、平台子網域） |
| `store/listing.md`、`README.md`、`CHANGELOG.md`、`docs/DEVELOPMENT.md` | 權限說明、攔截方式說明 |

順便處理：警告頁的「返回」按鈕在沒有上一頁時會導向 `chrome://newtab`，擴充功能可能不允許導向這類網址。實作時要先在 Chrome 實測；不行就改成關閉分頁（`chrome.tabs.remove`）或導向空白頁。

## 5. 需要先驗證（約半天）

先寫一個最小的實驗版本，確認下面幾點才動正式程式碼。任何一點不成立，就照「結果不成立時」那一欄調整設計：

| # | 要確認的事 | 結果不成立時 |
|---|---|---|
| 1 | 一條規則的 `requestDomains` 放 5 萬個網域可以運作；12 萬個網域分成 3 條規則，總共要多少規則數 | 縮小每段的網域數，增加規則數（動態規則上限遠大於需要） |
| 2 | 動態規則有沒有總大小上限；建立 12 萬個網域的規則要花多久、Service Worker 記憶體多少 | 改用靜態規則檔（`rule_resources`），並在 manifest 加 `key` 固定擴充功能 ID |
| 3 | `regexSubstitution` 可以轉到 `chrome-extension://` 頁面，網址帶有 `&`、`?`、中文時能完整保留 | 改用 3.2 的備案（`extensionPath`＋session 記錄） |
| 4 | `use_dynamic_url: true` 時，`runtime.getURL()` 回傳的網址轉址後能正常開啟 | 拿掉 `use_dynamic_url`，在文件中說明可被偵測的風險 |
| 5 | `frame-ancestors 'none'` 對擴充功能頁面有效 | 只靠 `window.top !== window` 的偵測 |
| 6 | session allow 規則（優先權 2）確實蓋過 redirect 規則（優先權 1） | 改在重建規則時用 `excludedRequestDomains` 排除放行網域 |
| 7 | 擴充功能被停用、再啟用之後，動態規則還在且正確 | 在 `onStartup`／`onInstalled` 一律重建 |

目前的最低 Chrome 版本是 114。各項上限要以 114 的數字為準（例如 Chrome 121 之前，動態規則總數上限較低）。

## 6. 測試計畫

延續現有的 Chrome E2E（CDP pipe）測試，新增：

1. **請求沒有送出：** 用 `--host-resolver-rules` 把測試網域指到本機伺服器。開啟名單網域後，伺服器的存取紀錄應該是 **0 筆**，分頁停在警告頁。這是這次改動最重要的驗收條件。
2. **原始網址完整：** 含 `?a=1&b=2`、路徑中文、很長的網址，警告頁顯示與「仍要前往」的目標都正確。
3. **子網域與共用平台：** `a.evil.com` 被擋；名單上有 `evil.workers.dev` 時，`other.workers.dev` 不被擋。
4. **放行：** 按「仍要前往」後可以進入，重新整理也不再被擋；重開瀏覽器後再擋一次。
5. **回報：** 回報後立刻生效（不用重新載入）；取消回報後解除。
6. **名單更新：** 模擬每週更新新增網域，新網域被擋；`dnrVersion` 相同時不重建。
7. **後備機制：** 讓 `updateDynamicRules` 失敗（注入錯誤），名單網站仍由軟攔截導向警告頁。
8. **規則判斷不受影響：** 現有 26＋12 項 E2E 全部通過。
9. **警告頁被嵌入：** 用 iframe 嵌入警告頁時，不顯示「仍要前往」。

效能：記錄建立規則的時間、Service Worker 記憶體，寫進 PR 說明。

## 7. 上線與回退

- 版本：**0.4.0**，在第一次上架前完成（理由見 3.8）。
- 回退：DNR 的部分集中在 `src/lib/dnr.js` 和 background 裡一個 `syncDnrRules()` 函式。出問題時拿掉呼叫、清空動態規則（`removeRuleIds` 全部），`onBeforeNavigate` 會自動接手（因為 `dnrVersion` 不存在）。

## 8. 工作量估計

| 項目 | 估計 |
|---|---|
| 第 5 節的實驗驗證 | 0.5 天 |
| `dnr.js`＋background＋警告頁 | 1 天 |
| E2E 測試（含「請求沒有送出」） | 0.5–1 天 |
| 文件、商店說明、CHANGELOG | 0.5 天 |
| **合計** | **約 2.5–3 天** |

## 9. 待決定

1. **子框架要不要擋？** 詐騙網頁偶爾會用 iframe 嵌入另一個詐騙網站。建議先只擋 `main_frame`（主頁面），之後依評估資料再決定。
2. **規則判斷為「危險」的網站要不要也改成硬攔截？** 做法是導航時判斷後，動態加入一條 session 規則，之後再開同一網站時就能在連線前擋下。第一次仍是軟攔截。建議等 ROADMAP 第 5 步調整完權重、確認誤判率後再決定。
3. **使用者能不能關掉硬攔截？** 建議不提供開關。名單來自 165 官方公告，誤判風險低，而且每次都可以按「仍要前往」放行。

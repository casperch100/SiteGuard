# SiteGuard 偵測評估報告

> 產生時間：2026-11-27 05:45 UTC　評估範圍：最近 28 天收集的詐騙網域

## 是否達標

| 指標 | 目標 | 只用規則 | 加上 165 名單 |
|---|---|---|---|
| 偵測率（可疑＋危險） | ≥ 50.0% | 53.1% ✅ | 53.1% ✅ |
| 其中判為「危險」 | — | 0.0% | 0.0% |
| 誤判率（正常網站被判可疑或危險） | ≤ 1.0% | 1.7% ❌ | 1.7% ❌ |
| 誤判率（只看查得到註冊日期的 739 個正常網站） | ≤ 1.0% | 1.2% ❌ | 1.2% ❌ |
| 樣本數 | — | 詐騙 550／正常 11986 | 詐騙 550／正常 11986 |

兩欄使用**同一批**樣本：收集時仍在線的詐騙網域（PhishTank 等），不含 165 樣本。「只用規則」代表新詐騙網站還沒進任何名單時的表現，是第一階段的主要目標。

參考：165 樣本 2487 個（多半在公布時已被刪除、查不到註冊日期），只用規則的偵測率 17.1%；它們本來就在 165 名單中，所以不列入上表比較。

## 最近的資料收集

| 時間（UTC） | 執行環境 | 來源 | 結果 | 下載筆數 | 近期通報 | 新增網域 | 查到註冊日期 | 備註 |
|---|---|---|---|---|---|---|---|---|
| 2026-11-27 00:24 | GitHub Actions | 165 | ✅ 成功 | 104541 | 9444 | 1322 | 951 | 資料月份 11510 |
| 2026-11-27 00:24 | GitHub Actions | phishtank | ✅ 成功 | 42532 | 514 | 0 | 0 |  |
| 2026-11-27 00:24 | GitHub Actions | phishtank | ✅ 成功 | 42532 | 514 | 16 | 15 |  |
| 2026-11-27 00:14 | 本機 | phishtank | ✅ 成功 | 42527 | 499 | 0 | 0 |  |

「近期通報」：PhishTank 是最近 72 小時內通報、已驗證且仍在線的網址數；165 是最新月份新增的網域數。「新增網域」不含之前已收集過的。

## 偵測率細項（只用規則）

| 分組 | 樣本 | 偵測率 | 危險 |
|---|---|---|---|
| 165 | 2487 | 17.1% | 0.2% |
| phishtank | 550 | 53.1% | 0.0% |
| 獨立網域 | 2868 | 24.9% | 0.2% |
| 共用平台子網域 | 169 | 3.0% | 0.0% |
| 查得到註冊日期 | 2307 | 30.9% | 0.2% |
| 查不到註冊日期 | 730 | 0.8% | 0.0% |

## 網域年齡（獨立網域，收集當下查詢）

- 查得到註冊日期：2307／2868　（RDAP 狀態：ok 2307、no_rdap 30、error 527、not_found 4）
- 中位數：81 天
- 30 天內：12.7%　90 天內：60.1%　一年內：90.6%

## 漏抓的詐騙網域（範例）

- `brt-yz.eu.cc`
- `brt-ys.eu.cc`
- `brt-yc.eu.cc`
- `brt-ya.eu.cc`
- `nubank-emprestimo.vercel.app`
- `brt-ix.eu.cc`
- `brt-yx.eu.cc`
- `nubankemprestimo.vercel.app`
- `login-nubank.vercel.app`
- `vendasoboticario.vercel.app`
- `itau.granometrics.io`
- `samimer-9f859.web.app`
- `scanned.page`
- `dragonflyshipctms-nl.eu.cc`
- `ephemeral-gingersnap-739019.netlify.app`

## 被誤判的正常網站（共 207 個，列出前 30 個）

- hicloudcam.com（suspicious 40：網址含有「icloud」字樣，但不是「Apple」的官方網站）
- googlevideo.com（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- googletagmanager.com（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- cloud.microsoft（suspicious 50：網址「cloud.microsoft」和「Apple」官方網站（icloud.com）只差 1 個字）
- apple-dns.net（suspicious 40：網址含有「apple」字樣，但不是「Apple」的官方網站）
- googlesyndication.com（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- googledomains.com（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- google-analytics.com（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- withgoogle.com（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- googletagservices.com（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- adtrafficquality.google（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- googleblog.com（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- cdn-apple.com（suspicious 40：網址含有「apple」字樣，但不是「Apple」的官方網站）
- googleadservices.com（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- google.cn（suspicious 45：網域名稱和「Google」官方網站（google.com）相同，但網域後綴不同）
- dns.google（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- facebook.net（suspicious 45：網域名稱和「Facebook」官方網站（facebook.com）相同，但網域後綴不同）
- myhuaweicloud.com（suspicious 40：網址含有「icloud」字樣，但不是「Apple」的官方網站）
- share.google（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- icloud-content.com（suspicious 40：網址含有「icloud」字樣，但不是「Apple」的官方網站）
- google.de（suspicious 45：網域名稱和「Google」官方網站（google.com）相同，但網域後綴不同）
- google.com.hk（suspicious 45：網域名稱和「Google」官方網站（google.com）相同，但網域後綴不同）
- hicloud.com（suspicious 50：網址「hicloud.com」和「Apple」官方網站（icloud.com）只差 1 個字）
- shopee.com.br（suspicious 45：網域名稱和「蝦皮購物」官方網站（shopee.tw）相同，但網域後綴不同）
- shopeemobile.com（suspicious 40：網址含有「shopee」字樣，但不是「蝦皮購物」的官方網站）
- googlezip.net（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- shopee.co.id（suspicious 40：網址含有「shopee」字樣，但不是「蝦皮購物」的官方網站）
- safebrowsing.apple（suspicious 40：網址含有「apple」字樣，但不是「Apple」的官方網站）
- google.co.uk（suspicious 45：網域名稱和「Google」官方網站（google.com）相同，但網域後綴不同）
- google.com.br（suspicious 45：網域名稱和「Google」官方網站（google.com）相同，但網域後綴不同）

---
資料來源：[PhishTank](https://phishtank.org/)（Cisco Talos）、內政部警政署 165 反詐騙諮詢專線、[Tranco](https://tranco-list.eu/) 熱門網站排行。

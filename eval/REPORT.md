# SiteGuard 偵測評估報告

> 產生時間：2026-11-26 23:58 UTC　評估範圍：最近 28 天收集的詐騙網域

## 是否達標

| 指標 | 目標 | 只用規則 | 加上 165 名單 |
|---|---|---|---|
| 偵測率（可疑＋危險） | ≥ 50.0% | 29.2% ❌ | 51.9% ✅ |
| 其中判為「危險」 | — | 0.1% | 0.0% |
| 誤判率（正常網站被判可疑或危險） | ≤ 1.0% | 1.7% ❌ | 1.7% ❌ |
| 誤判率（只看查得到註冊日期的 734 個正常網站） | ≤ 1.0% | 1.2% ❌ | 1.2% ❌ |
| 樣本數 | — | 詐騙 1182／正常 11986 | 詐騙 534／正常 11986 |

「只用規則」代表新詐騙網站還沒進任何名單時的表現，是第一階段的主要目標。「加上 165 名單」不計入來源是 165 的樣本（它們本來就在名單中）。

## 偵測率細項（只用規則）

| 分組 | 樣本 | 偵測率 | 危險 |
|---|---|---|---|
| 165 | 648 | 10.5% | 0.2% |
| phishtank | 534 | 51.9% | 0.0% |
| 獨立網域 | 1014 | 33.5% | 0.1% |
| 共用平台子網域 | 168 | 3.0% | 0.0% |
| 查得到註冊日期 | 921 | 36.8% | 0.1% |
| 查不到註冊日期 | 261 | 2.3% | 0.0% |

## 網域年齡（獨立網域，收集當下查詢）

- 查得到註冊日期：921／1014　（RDAP 狀態：ok 921、no_rdap 20、error 69、not_found 4）
- 中位數：68 天
- 30 天內：29.1%　90 天內：62.2%　一年內：83.6%

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
- shopee.com.br（suspicious 40：網址含有「shopee」字樣，但不是「蝦皮購物」的官方網站）
- shopeemobile.com（suspicious 40：網址含有「shopee」字樣，但不是「蝦皮購物」的官方網站）
- googlezip.net（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）
- shopee.co.id（suspicious 40：網址含有「shopee」字樣，但不是「蝦皮購物」的官方網站）
- safebrowsing.apple（suspicious 40：網址含有「apple」字樣，但不是「Apple」的官方網站）
- google.co.uk（suspicious 45：網域名稱和「Google」官方網站（google.com）相同，但網域後綴不同）
- google.com.br（suspicious 40：網址含有「google」字樣，但不是「Google」的官方網站）

---
資料來源：[PhishTank](https://phishtank.org/)（Cisco Talos）、內政部警政署 165 反詐騙諮詢專線、[Tranco](https://tranco-list.eu/) 熱門網站排行。

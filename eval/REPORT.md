# SiteGuard 偵測評估報告

> 產生時間：2026-11-26 13:13 UTC　評估範圍：最近 28 天收集的詐騙網域

## 是否達標

| 指標 | 目標 | 只用規則 | 加上 165 名單 |
|---|---|---|---|
| 偵測率（可疑＋危險） | ≥ 50.0% | 0.6% ❌ | 1.1% ❌ |
| 其中判為「危險」 | — | 0.0% | 0.0% |
| 誤判率（正常網站被判可疑或危險） | ≤ 1.0% | 1.7% ❌ | 1.7% ❌ |
| 樣本數 | — | 詐騙 1100／正常 11986 | 詐騙 452／正常 11986 |

「只用規則」代表新詐騙網站還沒進任何名單時的表現，是第一階段的主要目標。「加上 165 名單」不計入來源是 165 的樣本（它們本來就在名單中）。

## 偵測率細項（只用規則）

| 分組 | 樣本 | 偵測率 | 危險 |
|---|---|---|---|
| 165 | 648 | 0.3% | 0.0% |
| phishtank | 452 | 1.1% | 0.0% |
| 獨立網域 | 937 | 0.2% | 0.0% |
| 共用平台子網域 | 163 | 3.1% | 0.0% |

## 網域年齡（獨立網域，收集當下查詢）

- 查得到註冊日期：845／937　（RDAP 狀態：ok 845、no_rdap 19、error 69、not_found 4）
- 中位數：69 天
- 30 天內：26.4%　90 天內：61.9%　一年內：84.5%

## 漏抓的詐騙網域（範例）

- `allegro.authentication24.shop`
- `prime-europe.com`
- `allegrolokalnie.authentication24.shop`
- `allegrolokalnie.eofetta863.cfd`
- `allegro.eofetta863.cfd`
- `pt-gls.top`
- `brt-yz.eu.cc`
- `brt-ys.eu.cc`
- `brt-yc.eu.cc`
- `allegro.pl-oferta-7461-3819-3842.sbs`
- `brt-ya.eu.cc`
- `nubank-emprestimo.vercel.app`
- `brt-ix.eu.cc`
- `brt-yx.eu.cc`
- `nubankemprestimo.vercel.app`

## 被誤判的正常網站（共 206 個，列出前 30 個）

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

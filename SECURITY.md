# 安全性政策

## 支援的版本

只有最新版本會收到安全性修正。請先將 SiteGuard 更新到最新版本，再確認問題是否仍然存在。

## 回報安全性漏洞

如果你發現 SiteGuard 本身的安全性漏洞，例如：

- 可以讓惡意網頁繞過警告、竄改判斷結果，或讀取擴充功能的資料
- 擴充功能頁面（Popup、警告頁）有跨站腳本（XSS）等注入問題
- 名單更新流程可能被注入惡意資料

**請不要開公開的 Issue。** 請透過 GitHub 的私下回報功能：

👉 [私下回報安全性漏洞](https://github.com/casperch100/SiteGuard/security/advisories/new)

請盡量提供：

- 問題說明與可能的影響
- 重現步驟或概念驗證
- 受影響的版本

我們會盡快確認收到，並在修正後於 [CHANGELOG](CHANGELOG.md) 中致謝（如果你願意具名）。

## 不屬於安全性漏洞的情況

以下情況請用一般的 Issue 回報：

- **某個詐騙網站沒有被警告**：請用「[回報漏抓的詐騙網站](https://github.com/casperch100/SiteGuard/issues/new?template=missed-scam.yml)」。
- **某個正常網站被誤判**：請用「[回報誤判](https://github.com/casperch100/SiteGuard/issues/new?template=false-positive.yml)」。

如果你已經受騙，請撥打 **165 反詐騙諮詢專線**。

# 憑證鏈工具（CertChainTool）

Windows 原生 UI（Win32 + C++）的憑證小工具：把散落的多張憑證合成完整憑證鏈，並在各種格式之間轉換。
只使用 Windows 內建的 CryptoAPI / CNG，不需要 OpenSSL；輸出是單一 exe（靜態連結 CRT，不需安裝 runtime）。

## 功能

- **載入**：拖曳檔案/資料夾到視窗、開啟檔案（可多選）、Ctrl+V 貼上 PEM、命令列參數
  - 憑證：PEM（一個檔可含多張）、DER、PKCS#7（.p7b/.p7c）、PFX/P12、已簽章的 .exe/.dll
  - 私鑰：PKCS#8、RSA PKCS#1、EC（SEC1）；加密的 PKCS#8（PBES2/AES、PKCS#12 PBE）與 OpenSSL 傳統加密 PEM 皆可
- **自動建鏈**：依簽章關係排出「終端 → 中繼 → 根」，自動配對私鑰；不相關的憑證標示「不在鏈上」，可右鍵手動指定終端憑證
- **補齊並驗證（F5）**：交給 Windows 憑證鏈引擎，從本機存放區或網路（AIA）補上缺少的中繼/根憑證，並檢查信任、有效期與撤銷狀態
- **產生 CSR 與私鑰（Ctrl+N）**：RSA 2048/3072/4096、EC P-256/P-384，或沿用已載入的私鑰（續約）
  - 選取既有憑證後產生，會自動帶入主體與 SAN
  - 支援中文主體（UTF-8）、多個 SAN（網域、萬用字元、IPv4/IPv6）
  - 私鑰可用密碼加密（PBES2 / AES-256），CSR 內容自動複製到剪貼簿
  - 新私鑰會留在工具中，拿到 CA 簽發的憑證後拖進來即自動配對
- **產生自簽憑證**：同一個對話框選「產生自簽憑證」並設定有效天數，憑證與私鑰會直接載入，可馬上匯出成各種格式（測試、內部系統用）
- **匯出**（可選是否包含根憑證）
  - 完整憑證鏈 PEM（fullchain，nginx / Apache 2.4.8+）
  - 中繼憑證 PEM（CA bundle，Apache SSLCertificateChainFile 等）
  - 憑證鏈 + 私鑰合併 PEM（HAProxy 等）
  - PFX（AES-256，或 3DES 相容舊系統）、P7B
  - Java KeyStore（JKS，Tomcat 的 `.keystore` / `.jks`）：別名 `tomcat`，私鑰密碼與 KeyStore 密碼相同；沒有私鑰時匯出成 truststore
  - 私鑰 PEM（PKCS#8、傳統 RSA PKCS#1，或以密碼加密）
  - 單張憑證 PEM / DER、複製 PEM 到剪貼簿
- 雙擊（或 Enter）以 Windows 原生憑證對話框檢視，「憑證路徑」頁會使用已載入的憑證

私鑰只存在記憶體中，不會寫入 Windows 憑證存放區。

### Tomcat 設定範例

```xml
<!-- Tomcat 8.5 以上 -->
<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true">
  <SSLHostConfig>
    <Certificate certificateKeystoreFile="conf/tomcat.keystore"
                 certificateKeystorePassword="（匯出時設定的密碼）"
                 certificateKeyAlias="tomcat" />
  </SSLHostConfig>
</Connector>

<!-- Tomcat 7 / 8.0 -->
<Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true" scheme="https" secure="true"
           keystoreFile="conf/tomcat.keystore" keystorePass="（密碼）" keyAlias="tomcat" />
```

Java 8u60 以後的 Tomcat 也可以直接用匯出的 PFX（`certificateKeystoreType="PKCS12"`）；舊版 Java 讀不了 AES-256 的 PFX 時，請改用 3DES 或 JKS。

## 建置

需要 Visual Studio 2022（或 Build Tools）的「使用 C++ 的桌面開發」。

```bat
build.bat            :: 產生 build\CertChainTool.exe
```

## 測試

```bash
bash tests/make_testdata.sh tests/testdata   # 用 OpenSSL 產生測試憑證鏈與各種格式（Git for Windows 內建 openssl）
```
```bat
build.bat test                               :: 編譯並執行 build\selftest.exe
```

## 專案結構

| 檔案 | 內容 |
|---|---|
| `src/certcore.*` | 核心：解析、建鏈排序、私鑰配對、驗證、匯出、CSR 產生（不含 UI） |
| `src/main.cpp` | Win32 主視窗 |
| `src/app.rc`、`resource.h`、`app.manifest`、`app.ico` | 選單、快速鍵、對話框、DPI 與視覺樣式設定、圖示 |
| `tests/` | 測試資料產生腳本與命令列測試 |
| `tools/make_icon.ps1` | 重新產生圖示 |

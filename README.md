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
- **匯出**（可選是否包含根憑證）
  - 完整憑證鏈 PEM（fullchain，nginx / Apache 2.4.8+）
  - 中繼憑證 PEM（CA bundle，Apache SSLCertificateChainFile 等）
  - 憑證鏈 + 私鑰合併 PEM（HAProxy 等）
  - PFX（AES-256，或 3DES 相容舊系統）、P7B
  - 私鑰 PEM（PKCS#8、傳統 RSA PKCS#1，或以密碼加密）
  - 單張憑證 PEM / DER、複製 PEM 到剪貼簿
- 雙擊（或 Enter）以 Windows 原生憑證對話框檢視，「憑證路徑」頁會使用已載入的憑證

私鑰只存在記憶體中，不會寫入 Windows 憑證存放區。

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

// certcore.h - 憑證處理核心（不含 UI）
// 只使用 Windows 內建的 CryptoAPI / CNG（crypt32、ncrypt、bcrypt），不依賴 OpenSSL。
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS   // 讓 CERT_CHAIN_PARA 有 dwUrlRetrievalTimeout
#endif
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace cc {

using Bytes = std::vector<BYTE>;

// 以 shared_ptr 管理 PCCERT_CONTEXT 的生命週期
using CertPtr = std::shared_ptr<const CERT_CONTEXT>;
CertPtr WrapCert(PCCERT_CONTEXT ctx);                 // 取得所有權
CertPtr CertFromDer(const BYTE* p, size_t n);         // 從 DER 建立乾淨的 context（不帶任何屬性）

struct KeyItem {
    Bytes pkcs8;            // 明文 PKCS#8 PrivateKeyInfo (DER)
    Bytes publicKeyBits;    // 對應公鑰（SubjectPublicKeyInfo 的 BIT STRING 內容）
    std::wstring algName;   // 例："RSA 2048 bits"
    std::wstring source;    // 來源
};

struct CertItem {
    CertPtr cert;
    std::wstring source;
    int keyIndex = -1;      // 對應 keys[] 的索引，-1 表示沒有私鑰
};

enum class Role { Leaf, Intermediate, Root, Unused };

struct OrderEntry {
    int certIndex;
    Role role;
    bool issuerMissing;     // 非自簽，但在清單中找不到簽發者
};

// 載入時需要密碼時呼叫。回傳 false 代表使用者取消。
using PasswordPrompt = std::function<bool(const std::wstring& prompt, std::wstring& password)>;

struct LoadResult {
    int certsAdded = 0;
    int certsDuplicated = 0;
    int keysAdded = 0;
    std::vector<std::wstring> messages;   // 錯誤或提示訊息
};

// Windows 憑證鏈引擎的驗證結果
struct ChainReport {
    bool ok = false;                      // CertGetCertificateChain 是否成功執行
    std::wstring error;
    DWORD errorStatus = 0;                // 整條鏈的 CERT_TRUST_* 錯誤
    std::vector<CertPtr> elements;        // 終端 → 根
    std::vector<DWORD> elementErrors;
};

class Workspace {
public:
    std::vector<CertItem> certs;
    std::vector<KeyItem> keys;
    const CERT_CONTEXT* leafOverride = nullptr;   // 使用者手動指定的終端憑證

    LoadResult LoadFile(const std::wstring& path, const PasswordPrompt& prompt);
    LoadResult LoadBytes(const Bytes& data, const std::wstring& source, const PasswordPrompt& prompt);

    // 加入憑證；重複時回傳 false
    bool AddCert(const CertPtr& cert, const std::wstring& source);
    // 加入私鑰（明文 PKCS#8）；重複時回傳 false
    bool AddKey(const Bytes& pkcs8, const std::wstring& source, std::wstring& err);

    void RemoveCert(int index);
    void RemoveKey(int index);
    void Clear();

    void MatchKeys();                     // 重新配對憑證與私鑰
    std::vector<OrderEntry> BuildOrder() const;   // 憑證鏈在前（終端→根），未使用的在後
    std::vector<int> UnmatchedKeys() const;
    int FindCert(const CERT_CONTEXT* ctx) const;

private:
    void LoadPem(const std::string& text, const std::wstring& source, const PasswordPrompt& prompt, LoadResult& r);
    void LoadBinary(const Bytes& data, const std::wstring& source, const PasswordPrompt& prompt, LoadResult& r);
    void LoadPfx(const Bytes& data, const std::wstring& source, const PasswordPrompt& prompt, LoadResult& r);
    void LoadStoreBlob(const Bytes& data, const std::wstring& source, LoadResult& r, bool& recognized);
};

// ---- 憑證資訊 ----
std::wstring CertDisplayName(PCCERT_CONTEXT c);        // 主體簡稱 (CN)
std::wstring CertIssuerDisplayName(PCCERT_CONTEXT c);
std::wstring CertDN(const CERT_NAME_BLOB& name);
std::wstring FormatFileTime(const FILETIME& ft, bool withTime = true);
std::wstring Thumbprint(PCCERT_CONTEXT c, LPCWSTR alg);   // BCRYPT_SHA1_ALGORITHM / BCRYPT_SHA256_ALGORITHM
std::wstring SerialHex(PCCERT_CONTEXT c);
bool IsSelfSigned(PCCERT_CONTEXT c);
bool IsCA(PCCERT_CONTEXT c);
bool IsIssuerOf(PCCERT_CONTEXT issuer, PCCERT_CONTEXT subject);
int  DaysRemaining(PCCERT_CONTEXT c);                   // 負數表示已過期
bool NotYetValid(PCCERT_CONTEXT c);
std::wstring DescribeCert(PCCERT_CONTEXT c);            // 多行明細（CRLF）
std::wstring TrustErrorText(DWORD status, bool* onlyWarnings = nullptr);

// ---- 驗證 ----
ChainReport BuildSystemChain(const CertPtr& leaf, const std::vector<CertPtr>& extra, bool checkRevocation);

// ---- 匯出 ----
std::string CertToPem(PCCERT_CONTEXT c);
std::string KeyToPem(const Bytes& pkcs8);                   // -----BEGIN PRIVATE KEY-----
bool KeyToPkcs1Pem(const Bytes& pkcs8, std::string& out, std::wstring& err);   // -----BEGIN RSA PRIVATE KEY-----
bool ExportP7b(const std::vector<CertPtr>& certs, Bytes& out, std::wstring& err);
bool ExportPfx(const std::vector<CertPtr>& chain, const KeyItem* leafKey, const std::wstring& password,
               bool aes256, Bytes& out, std::wstring& err);

// ---- CSR / 私鑰產生 ----
enum class KeyType { Rsa2048, Rsa3072, Rsa4096, EcP256, EcP384 };

struct CsrRequest {
    std::wstring cn, o, ou, l, st, c, email;
    std::vector<std::wstring> sans;   // DNS 名稱或 IP；可加 "DNS:" / "IP:" 前綴
    KeyType keyType = KeyType::Rsa2048;
    const Bytes* existingKey = nullptr;   // 不為 null 時改用這把私鑰（PKCS#8）
};

// 產生 CSR（DER）。若未指定 existingKey 會產生新私鑰並由 keyPkcs8 傳回。
bool GenerateCsr(const CsrRequest& req, Bytes& csrDer, Bytes& keyPkcs8, std::wstring& err);
std::string CsrToPem(const Bytes& csrDer);
// 以 PBES2（PBKDF2-HMAC-SHA256 + AES-256-CBC）加密，輸出 -----BEGIN ENCRYPTED PRIVATE KEY-----
bool KeyToEncryptedPem(const Bytes& pkcs8, const std::wstring& password, std::string& out, std::wstring& err);

// ---- 工具 ----
std::string ToUtf8(const std::wstring& s);
std::wstring FromUtf8(const std::string& s);
std::wstring LastErrorText(DWORD err);
bool ReadAll(const std::wstring& path, Bytes& out);
bool WriteAll(const std::wstring& path, const void* p, size_t n);

}  // namespace cc

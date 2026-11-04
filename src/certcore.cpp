// certcore.cpp - 憑證處理核心實作
#include "certcore.h"

#include <bcrypt.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <map>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

namespace cc {

// ============================================================================
// 一般工具
// ============================================================================

std::string ToUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string r(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), r.data(), n, nullptr, nullptr);
    return r;
}

std::wstring FromUtf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring r(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), r.data(), n);
    return r;
}

std::wstring LastErrorText(DWORD err) {
    wchar_t* buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, err, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring s;
    if (n && buf) {
        s.assign(buf, n);
        LocalFree(buf);
        while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n' || s.back() == L' ' || s.back() == L'.' || s.back() == L'。'))
            s.pop_back();
    }
    wchar_t code[32];
    swprintf_s(code, L"0x%08X", err);
    return s.empty() ? std::wstring(L"錯誤碼 ") + code : s + L" (" + code + L")";
}

bool ReadAll(const std::wstring& path, Bytes& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    bool ok = GetFileSizeEx(h, &size) && size.QuadPart < 64ll * 1024 * 1024;
    if (ok) {
        out.resize((size_t)size.QuadPart);
        DWORD got = 0;
        ok = out.empty() || (ReadFile(h, out.data(), (DWORD)out.size(), &got, nullptr) && got == out.size());
    }
    CloseHandle(h);
    return ok;
}

bool WriteAll(const std::wstring& path, const void* p, size_t n) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD put = 0;
    bool ok = n == 0 || (WriteFile(h, p, (DWORD)n, &put, nullptr) && put == n);
    CloseHandle(h);
    return ok;
}

static Bytes Base64Decode(const std::string& s) {
    DWORD cb = 0;
    if (!CryptStringToBinaryA(s.data(), (DWORD)s.size(), CRYPT_STRING_BASE64, nullptr, &cb, nullptr, nullptr)) return {};
    Bytes out(cb);
    if (!CryptStringToBinaryA(s.data(), (DWORD)s.size(), CRYPT_STRING_BASE64, out.data(), &cb, nullptr, nullptr)) return {};
    out.resize(cb);
    return out;
}

static std::string PemBlock(const char* label, const BYTE* p, size_t n) {
    DWORD cch = 0;
    CryptBinaryToStringA(p, (DWORD)n, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &cch);
    std::string b64(cch, '\0');
    CryptBinaryToStringA(p, (DWORD)n, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64.data(), &cch);
    b64.resize(strlen(b64.c_str()));
    std::string out = std::string("-----BEGIN ") + label + "-----\n";
    for (size_t i = 0; i < b64.size(); i += 64) out += b64.substr(i, 64) + "\n";
    out += std::string("-----END ") + label + "-----\n";
    return out;
}

static std::wstring Hex(const BYTE* p, size_t n, bool reverse = false) {
    static const wchar_t* digits = L"0123456789ABCDEF";
    std::wstring s;
    for (size_t i = 0; i < n; i++) {
        BYTE b = reverse ? p[n - 1 - i] : p[i];
        s += digits[b >> 4];
        s += digits[b & 15];
    }
    return s;
}

static bool ParseHex(const std::string& s, Bytes& out) {
    out.clear();
    if (s.size() % 2) return false;
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned v = 0;
        if (sscanf_s(s.substr(i, 2).c_str(), "%2x", &v) != 1) return false;
        out.push_back((BYTE)v);
    }
    return true;
}

static std::string Trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static std::wstring FileNameOf(const std::wstring& path) {
    size_t p = path.find_last_of(L"\\/");
    return p == std::wstring::npos ? path : path.substr(p + 1);
}

// ============================================================================
// 簡易 DER 解析（只用於讀取私鑰的加密參數與 EC 曲線）
// ============================================================================

struct Der {
    BYTE tag = 0;
    const BYTE* p = nullptr;   // 內容
    size_t len = 0;
    const BYTE* raw = nullptr; // 含 tag/length 的完整 TLV
    size_t rawLen = 0;
};

static bool DerRead(const BYTE*& cur, const BYTE* end, Der& d) {
    if (cur >= end) return false;
    d.raw = cur;
    d.tag = *cur++;
    if ((d.tag & 0x1F) == 0x1F || cur >= end) return false;
    size_t len = *cur++;
    if (len & 0x80) {
        int nb = (int)(len & 0x7F);
        if (nb == 0 || nb > 4 || end - cur < nb) return false;
        len = 0;
        while (nb--) len = (len << 8) | *cur++;
    }
    if ((size_t)(end - cur) < len) return false;
    d.p = cur;
    d.len = len;
    cur += len;
    d.rawLen = (size_t)(cur - d.raw);
    return true;
}

static bool DerParse(const BYTE* p, size_t n, Der& d) {
    const BYTE* cur = p;
    return DerRead(cur, p + n, d);
}

static bool DerChildren(const Der& d, std::vector<Der>& out) {
    out.clear();
    const BYTE* cur = d.p;
    const BYTE* end = d.p + d.len;
    while (cur < end) {
        Der x;
        if (!DerRead(cur, end, x)) return false;
        out.push_back(x);
    }
    return true;
}

static bool OidIs(const Der& d, std::initializer_list<BYTE> oid) {
    return d.tag == 0x06 && d.len == oid.size() && memcmp(d.p, oid.begin(), d.len) == 0;
}

static bool DerUInt(const Der& d, unsigned long& v) {
    if (d.tag != 0x02 || d.len == 0 || d.len > 5) return false;
    v = 0;
    for (size_t i = 0; i < d.len; i++) v = (v << 8) | d.p[i];
    return true;
}

// ============================================================================
// 雜湊 / 對稱解密（BCrypt）
// ============================================================================

static bool HashData(LPCWSTR alg, const Bytes& in, Bytes& out) {
    BCRYPT_ALG_HANDLE a = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&a, alg, nullptr, 0))) return false;
    DWORD len = 0, cb = 0;
    BCryptGetProperty(a, BCRYPT_HASH_LENGTH, (PUCHAR)&len, sizeof(len), &cb, 0);
    out.resize(len);
    NTSTATUS st = BCryptHash(a, nullptr, 0, (PUCHAR)in.data(), (ULONG)in.size(), out.data(), len);
    BCryptCloseAlgorithmProvider(a, 0);
    return BCRYPT_SUCCESS(st);
}

static bool SymDecrypt(LPCWSTR alg, const Bytes& key, const Bytes& iv, const BYTE* data, size_t n, Bytes& out) {
    BCRYPT_ALG_HANDLE a = nullptr;
    BCRYPT_KEY_HANDLE k = nullptr;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&a, alg, nullptr, 0)) &&
        BCRYPT_SUCCESS(BCryptSetProperty(a, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) &&
        BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(a, &k, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0))) {
        Bytes ivc = iv;
        ULONG cb = 0;
        if (BCRYPT_SUCCESS(BCryptDecrypt(k, (PUCHAR)data, (ULONG)n, nullptr, ivc.data(), (ULONG)ivc.size(), nullptr, 0, &cb, BCRYPT_BLOCK_PADDING))) {
            out.resize(cb);
            ivc = iv;
            ok = BCRYPT_SUCCESS(BCryptDecrypt(k, (PUCHAR)data, (ULONG)n, nullptr, ivc.data(), (ULONG)ivc.size(), out.data(), cb, &cb, BCRYPT_BLOCK_PADDING));
            out.resize(cb);
        }
    }
    if (k) BCryptDestroyKey(k);
    if (a) BCryptCloseAlgorithmProvider(a, 0);
    return ok;
}

// ============================================================================
// 私鑰（CNG）
// ============================================================================

struct NcHandle {
    NCRYPT_HANDLE h = 0;
    NcHandle() = default;
    explicit NcHandle(NCRYPT_HANDLE x) : h(x) {}
    NcHandle(const NcHandle&) = delete;
    NcHandle& operator=(const NcHandle&) = delete;
    ~NcHandle() { if (h) NCryptFreeObject(h); }
};

// 匯入 PKCS#8（明文或 PKCS#12 PBE 加密）為暫時性金鑰，並允許匯出明文
static SECURITY_STATUS ImportPkcs8(const Bytes& blob, const wchar_t* password, NCRYPT_KEY_HANDLE* out) {
    *out = 0;
    NCRYPT_PROV_HANDLE prov = 0;
    SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (st != ERROR_SUCCESS) return st;
    NcHandle provGuard(prov);

    NCryptBuffer buf[1] = {};
    NCryptBufferDesc desc = {NCRYPTBUFFER_VERSION, 0, buf};
    if (password) {
        buf[0].cbBuffer = (ULONG)((wcslen(password) + 1) * sizeof(wchar_t));
        buf[0].BufferType = NCRYPTBUFFER_PKCS_SECRET;
        buf[0].pvBuffer = (PVOID)password;
        desc.cBuffers = 1;
    }
    NCRYPT_KEY_HANDLE h = 0;
    st = NCryptImportKey(prov, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, password ? &desc : nullptr, &h,
                         (PBYTE)blob.data(), (DWORD)blob.size(), NCRYPT_DO_NOT_FINALIZE_FLAG);
    if (st != ERROR_SUCCESS) return st;
    DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    st = NCryptSetProperty(h, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&policy, sizeof(policy), NCRYPT_PERSIST_FLAG);
    if (st == ERROR_SUCCESS) st = NCryptFinalizeKey(h, 0);
    if (st != ERROR_SUCCESS) {
        NCryptFreeObject(h);
        return st;
    }
    *out = h;
    return ERROR_SUCCESS;
}

static SECURITY_STATUS ExportPlain(NCRYPT_KEY_HANDLE h, Bytes& out) {
    DWORD cb = 0;
    SECURITY_STATUS st = NCryptExportKey(h, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr, nullptr, 0, &cb, 0);
    if (st != ERROR_SUCCESS) return st;
    out.resize(cb);
    st = NCryptExportKey(h, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr, out.data(), cb, &cb, 0);
    out.resize(cb);
    return st;
}

// 從 CNG 金鑰取得明文 PKCS#8。
// 若金鑰只允許「加密匯出」（例如從 PFX 匯入的金鑰），先以暫時密碼加密匯出，
// 再匯入成允許明文匯出的暫時性金鑰。
static SECURITY_STATUS ExportPkcs8FromHandle(NCRYPT_KEY_HANDLE h, Bytes& out) {
    if (ExportPlain(h, out) == ERROR_SUCCESS) return ERROR_SUCCESS;

    static wchar_t tmpPwd[] = L"cermaker-transfer";
    struct {
        CRYPT_PKCS12_PBE_PARAMS params;
        BYTE salt[8];
    } pbe = {};
    pbe.params.iIterations = 1;
    pbe.params.cbSalt = sizeof(pbe.salt);
    BCryptGenRandom(nullptr, pbe.salt, sizeof(pbe.salt), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    static char algOid[] = "1.2.840.113549.1.12.1.3";   // pbeWithSHAAnd3-KeyTripleDES-CBC
    NCryptBuffer b[3] = {
        {(ULONG)sizeof(tmpPwd), NCRYPTBUFFER_PKCS_SECRET, tmpPwd},
        {(ULONG)sizeof(algOid), NCRYPTBUFFER_PKCS_ALG_OID, algOid},
        {(ULONG)sizeof(pbe), NCRYPTBUFFER_PKCS_ALG_PARAM, &pbe},
    };
    NCryptBufferDesc desc = {NCRYPTBUFFER_VERSION, 3, b};
    DWORD cb = 0;
    SECURITY_STATUS st = NCryptExportKey(h, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &desc, nullptr, 0, &cb, 0);
    if (st != ERROR_SUCCESS) return st;
    Bytes enc(cb);
    st = NCryptExportKey(h, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &desc, enc.data(), cb, &cb, 0);
    if (st != ERROR_SUCCESS) return st;
    enc.resize(cb);
    NCRYPT_KEY_HANDLE h2 = 0;
    st = ImportPkcs8(enc, tmpPwd, &h2);
    if (st != ERROR_SUCCESS) return st;
    NcHandle g(h2);
    return ExportPlain(h2, out);
}

static bool DescribeKeyHandle(NCRYPT_KEY_HANDLE h, KeyItem& k, std::wstring& err) {
    wchar_t group[64] = {};
    DWORD cb = 0;
    NCryptGetProperty(h, NCRYPT_ALGORITHM_GROUP_PROPERTY, (PBYTE)group, sizeof(group) - sizeof(wchar_t), &cb, 0);
    DWORD bits = 0;
    NCryptGetProperty(h, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof(bits), &cb, 0);
    std::wstring name = group;
    if (name == L"ECDSA" || name == L"ECDH") {
        wchar_t curve[64] = {};
        if (NCryptGetProperty(h, NCRYPT_ECC_CURVE_NAME_PROPERTY, (PBYTE)curve, sizeof(curve) - sizeof(wchar_t), &cb, 0) == ERROR_SUCCESS)
            name = std::wstring(L"EC ") + curve;
        else
            name = L"EC";
    }
    k.algName = name + L" " + std::to_wstring(bits) + L" bits";

    DWORD cbInfo = 0;
    if (!CryptExportPublicKeyInfo(h, 0, X509_ASN_ENCODING, nullptr, &cbInfo)) {
        err = L"無法取得私鑰對應的公鑰：" + LastErrorText(GetLastError());
        return false;
    }
    Bytes info(cbInfo);
    auto pInfo = (PCERT_PUBLIC_KEY_INFO)info.data();
    if (!CryptExportPublicKeyInfo(h, 0, X509_ASN_ENCODING, pInfo, &cbInfo)) {
        err = L"無法取得私鑰對應的公鑰：" + LastErrorText(GetLastError());
        return false;
    }
    k.publicKeyBits.assign(pInfo->PublicKey.pbData, pInfo->PublicKey.pbData + pInfo->PublicKey.cbData);
    return true;
}

// 包成 PKCS#8 PrivateKeyInfo
static bool WrapPkcs8(const char* oid, const BYTE* params, size_t cbParams, const Bytes& inner, Bytes& out) {
    CRYPT_PRIVATE_KEY_INFO pki = {};
    pki.Version = 0;
    pki.Algorithm.pszObjId = (LPSTR)oid;
    pki.Algorithm.Parameters.pbData = (BYTE*)params;
    pki.Algorithm.Parameters.cbData = (DWORD)cbParams;
    pki.PrivateKey.pbData = (BYTE*)inner.data();
    pki.PrivateKey.cbData = (DWORD)inner.size();
    BYTE* p = nullptr;
    DWORD cb = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, &pki, CRYPT_ENCODE_ALLOC_FLAG, nullptr, &p, &cb)) return false;
    out.assign(p, p + cb);
    LocalFree(p);
    return true;
}

static bool RsaPkcs1ToPkcs8(const Bytes& pkcs1, Bytes& out) {
    static const BYTE nullParams[] = {0x05, 0x00};
    return WrapPkcs8(szOID_RSA_RSA, nullParams, sizeof(nullParams), pkcs1, out);
}

// SEC1 ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING, [0] parameters, [1] publicKey }
static bool EcSec1ToPkcs8(const Bytes& sec1, Bytes& out, std::wstring& err) {
    Der top;
    std::vector<Der> kids;
    if (!DerParse(sec1.data(), sec1.size(), top) || top.tag != 0x30 || !DerChildren(top, kids) || kids.size() < 2 ||
        kids[0].tag != 0x02 || kids[1].tag != 0x04) {
        err = L"EC 私鑰格式錯誤";
        return false;
    }
    for (auto& k : kids) {
        if (k.tag == 0xA0) {
            Der oid;
            if (DerParse(k.p, k.len, oid) && oid.tag == 0x06)
                return WrapPkcs8(szOID_ECC_PUBLIC_KEY, oid.raw, oid.rawLen, sec1, out);
        }
    }
    err = L"EC 私鑰缺少曲線參數，請以 openssl ec -param_enc named_curve 重新輸出";
    return false;
}

// PBES2（PBKDF2 + AES/3DES-CBC）加密的 PKCS#8 解密。OpenSSL 1.1 以後預設使用此格式。
// 回傳：0 成功、1 密碼錯誤、2 不支援
static int DecryptPbes2(const Bytes& epki, const std::wstring& password, Bytes& out, std::wstring& err) {
    Der top, encAlg, encData, oid, params, kdf, kdfOid, kdfParams, cipher, cipherOid, iv;
    std::vector<Der> k1, k2, k3, k4, k5, k6;
    if (!DerParse(epki.data(), epki.size(), top) || !DerChildren(top, k1) || k1.size() != 2) return 2;
    encAlg = k1[0];
    encData = k1[1];
    if (!DerChildren(encAlg, k2) || k2.size() != 2 || !DerChildren(k2[1], k3) || k3.size() != 2) return 2;
    kdf = k3[0];
    cipher = k3[1];
    if (!DerChildren(kdf, k4) || k4.size() != 2 || !OidIs(k4[0], {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C})) {
        err = L"不支援的金鑰衍生函式（只支援 PBKDF2）";
        return 2;
    }
    if (!DerChildren(k4[1], k5) || k5.size() < 2 || k5[0].tag != 0x04) return 2;
    Bytes salt(k5[0].p, k5[0].p + k5[0].len);
    unsigned long iter = 0;
    if (!DerUInt(k5[1], iter)) return 2;
    LPCWSTR prf = BCRYPT_SHA1_ALGORITHM;
    for (size_t i = 2; i < k5.size(); i++) {
        std::vector<Der> pk;
        if (k5[i].tag == 0x30 && DerChildren(k5[i], pk) && !pk.empty()) {
            if (OidIs(pk[0], {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07})) prf = BCRYPT_SHA1_ALGORITHM;
            else if (OidIs(pk[0], {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09})) prf = BCRYPT_SHA256_ALGORITHM;
            else if (OidIs(pk[0], {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A})) prf = BCRYPT_SHA384_ALGORITHM;
            else if (OidIs(pk[0], {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B})) prf = BCRYPT_SHA512_ALGORITHM;
            else { err = L"不支援的 PBKDF2 雜湊演算法"; return 2; }
        }
    }
    if (!DerChildren(cipher, k6) || k6.size() != 2 || k6[1].tag != 0x04) {
        err = L"不支援的加密演算法";
        return 2;
    }
    LPCWSTR symAlg = nullptr;
    size_t keyLen = 0;
    const Der& c = k6[0];
    if (OidIs(c, {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02})) { symAlg = BCRYPT_AES_ALGORITHM; keyLen = 16; }
    else if (OidIs(c, {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16})) { symAlg = BCRYPT_AES_ALGORITHM; keyLen = 24; }
    else if (OidIs(c, {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A})) { symAlg = BCRYPT_AES_ALGORITHM; keyLen = 32; }
    else if (OidIs(c, {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07})) { symAlg = BCRYPT_3DES_ALGORITHM; keyLen = 24; }
    else { err = L"不支援的加密演算法（支援 AES-CBC、3DES-CBC）"; return 2; }
    Bytes ivb(k6[1].p, k6[1].p + k6[1].len);

    std::string pwd = ToUtf8(password);
    BCRYPT_ALG_HANDLE hPrf = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hPrf, prf, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))) return 2;
    Bytes key(keyLen);
    NTSTATUS st = BCryptDeriveKeyPBKDF2(hPrf, (PUCHAR)pwd.data(), (ULONG)pwd.size(), salt.data(), (ULONG)salt.size(),
                                        iter, key.data(), (ULONG)key.size(), 0);
    BCryptCloseAlgorithmProvider(hPrf, 0);
    if (!BCRYPT_SUCCESS(st)) return 2;
    if (!SymDecrypt(symAlg, key, ivb, encData.p, encData.len, out)) return 1;
    // 驗證解出來的是 PrivateKeyInfo
    CRYPT_PRIVATE_KEY_INFO* pki = nullptr;
    DWORD cb = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, out.data(), (DWORD)out.size(), CRYPT_DECODE_ALLOC_FLAG, nullptr, &pki, &cb))
        return 1;
    LocalFree(pki);
    return 0;
}

// 解密 ENCRYPTED PRIVATE KEY。回傳：0 成功、1 密碼錯誤、2 不支援/錯誤
static int DecryptEncryptedPkcs8(const Bytes& epki, const std::wstring& password, Bytes& out, std::wstring& err) {
    Der top, alg, oid;
    std::vector<Der> k1, k2;
    if (!DerParse(epki.data(), epki.size(), top) || !DerChildren(top, k1) || k1.size() != 2 || !DerChildren(k1[0], k2) || k2.empty()) {
        err = L"加密私鑰格式錯誤";
        return 2;
    }
    if (OidIs(k2[0], {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D}))   // PBES2
        return DecryptPbes2(epki, password, out, err);
    // 其餘（PKCS#12 PBE）交給 CNG
    NCRYPT_KEY_HANDLE h = 0;
    SECURITY_STATUS st = ImportPkcs8(epki, password.c_str(), &h);
    if (st != ERROR_SUCCESS) return 1;
    NcHandle g(h);
    st = ExportPlain(h, out);
    if (st != ERROR_SUCCESS) {
        err = L"無法匯出私鑰：" + LastErrorText(st);
        return 2;
    }
    return 0;
}

// OpenSSL 傳統加密 PEM（Proc-Type: 4,ENCRYPTED / DEK-Info）。回傳：0 成功、1 密碼錯誤、2 不支援
static int DecryptLegacyPem(const Bytes& data, const std::string& dekInfo, const std::wstring& password, Bytes& out, std::wstring& err) {
    size_t comma = dekInfo.find(',');
    if (comma == std::string::npos) return 2;
    std::string cipher = Trim(dekInfo.substr(0, comma));
    for (auto& ch : cipher) ch = (char)toupper((unsigned char)ch);
    Bytes iv;
    if (!ParseHex(Trim(dekInfo.substr(comma + 1)), iv) || iv.size() < 8) return 2;
    LPCWSTR alg;
    size_t keyLen;
    if (cipher == "AES-128-CBC") { alg = BCRYPT_AES_ALGORITHM; keyLen = 16; }
    else if (cipher == "AES-192-CBC") { alg = BCRYPT_AES_ALGORITHM; keyLen = 24; }
    else if (cipher == "AES-256-CBC") { alg = BCRYPT_AES_ALGORITHM; keyLen = 32; }
    else if (cipher == "DES-EDE3-CBC") { alg = BCRYPT_3DES_ALGORITHM; keyLen = 24; }
    else if (cipher == "DES-CBC") { alg = BCRYPT_DES_ALGORITHM; keyLen = 8; }
    else { err = L"不支援的傳統 PEM 加密方式：" + FromUtf8(cipher); return 2; }

    // EVP_BytesToKey(MD5, salt = IV 前 8 bytes, count = 1)
    std::string pwd = ToUtf8(password);
    Bytes key, prev;
    while (key.size() < keyLen) {
        Bytes in = prev;
        in.insert(in.end(), pwd.begin(), pwd.end());
        in.insert(in.end(), iv.begin(), iv.begin() + 8);
        if (!HashData(BCRYPT_MD5_ALGORITHM, in, prev)) return 2;
        key.insert(key.end(), prev.begin(), prev.end());
    }
    key.resize(keyLen);
    if (!SymDecrypt(alg, key, iv, data.data(), data.size(), out)) return 1;
    Der d;
    if (!DerParse(out.data(), out.size(), d) || d.tag != 0x30 || d.rawLen != out.size()) return 1;
    return 0;
}

// ============================================================================
// 憑證資訊
// ============================================================================

CertPtr WrapCert(PCCERT_CONTEXT ctx) {
    if (!ctx) return nullptr;
    return CertPtr(ctx, [](const CERT_CONTEXT* c) { CertFreeCertificateContext(c); });
}

CertPtr CertFromDer(const BYTE* p, size_t n) {
    return WrapCert(CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, p, (DWORD)n));
}

std::wstring CertDisplayName(PCCERT_CONTEXT c) {
    wchar_t buf[512] = {};
    CertGetNameStringW(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf, 512);
    return buf;
}

std::wstring CertIssuerDisplayName(PCCERT_CONTEXT c) {
    wchar_t buf[512] = {};
    CertGetNameStringW(c, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, buf, 512);
    return buf;
}

std::wstring CertDN(const CERT_NAME_BLOB& name) {
    DWORD flags = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
    DWORD n = CertNameToStrW(X509_ASN_ENCODING, (PCERT_NAME_BLOB)&name, flags, nullptr, 0);
    std::wstring s(n, L'\0');
    CertNameToStrW(X509_ASN_ENCODING, (PCERT_NAME_BLOB)&name, flags, s.data(), n);
    s.resize(wcslen(s.c_str()));
    return s;
}

std::wstring FormatFileTime(const FILETIME& ft, bool withTime) {
    SYSTEMTIME utc, local;
    FileTimeToSystemTime(&ft, &utc);
    SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local);
    wchar_t buf[64];
    if (withTime)
        swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u", local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute, local.wSecond);
    else
        swprintf_s(buf, L"%04u-%02u-%02u", local.wYear, local.wMonth, local.wDay);
    return buf;
}

std::wstring Thumbprint(PCCERT_CONTEXT c, LPCWSTR alg) {
    BYTE hash[64];
    DWORD cb = sizeof(hash);
    if (!CryptHashCertificate2(alg, 0, nullptr, c->pbCertEncoded, c->cbCertEncoded, hash, &cb)) return L"";
    return Hex(hash, cb);
}

std::wstring SerialHex(PCCERT_CONTEXT c) {
    return Hex(c->pCertInfo->SerialNumber.pbData, c->pCertInfo->SerialNumber.cbData, true);
}

bool IsIssuerOf(PCCERT_CONTEXT issuer, PCCERT_CONTEXT subject) {
    if (!CertCompareCertificateName(X509_ASN_ENCODING, &subject->pCertInfo->Issuer, &issuer->pCertInfo->Subject)) return false;
    return CryptVerifyCertificateSignatureEx(0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void*)subject,
                                             CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)issuer, 0, nullptr) != FALSE;
}

bool IsSelfSigned(PCCERT_CONTEXT c) { return IsIssuerOf(c, c); }

bool IsCA(PCCERT_CONTEXT c) {
    PCERT_EXTENSION ext = CertFindExtension(szOID_BASIC_CONSTRAINTS2, c->pCertInfo->cExtension, c->pCertInfo->rgExtension);
    if (!ext) return false;
    CERT_BASIC_CONSTRAINTS2_INFO info = {};
    DWORD cb = sizeof(info);
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2, ext->Value.pbData, ext->Value.cbData, 0, nullptr, &info, &cb))
        return false;
    return info.fCA != FALSE;
}

static ULONGLONG FtToU64(const FILETIME& ft) { return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime; }

static ULONGLONG NowU64() {
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    return FtToU64(now);
}

int DaysRemaining(PCCERT_CONTEXT c) {
    long long diff = (long long)(FtToU64(c->pCertInfo->NotAfter) - NowU64());
    const long long day = 864000000000ll;
    return (int)(diff >= 0 ? diff / day : -((-diff + day - 1) / day));
}

bool NotYetValid(PCCERT_CONTEXT c) { return NowU64() < FtToU64(c->pCertInfo->NotBefore); }

static std::wstring OidName(LPCSTR oid, DWORD group = 0) {
    PCCRYPT_OID_INFO info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (void*)oid, group);
    if (info && info->pwszName && *info->pwszName) return info->pwszName;
    return FromUtf8(oid ? oid : "");
}

std::wstring DescribeCert(PCCERT_CONTEXT c) {
    const CERT_INFO* ci = c->pCertInfo;
    std::wstring s;
    auto line = [&](const std::wstring& k, const std::wstring& v) { s += k + L"：" + v + L"\r\n"; };

    line(L"主體 (Subject)", CertDN(ci->Subject));
    line(L"簽發者 (Issuer)", CertDN(ci->Issuer));
    line(L"序號", SerialHex(c));
    line(L"有效期間", FormatFileTime(ci->NotBefore) + L"  ～  " + FormatFileTime(ci->NotAfter));
    int days = DaysRemaining(c);
    if (NotYetValid(c)) line(L"狀態", L"尚未生效");
    else if (days < 0) line(L"狀態", L"已過期 " + std::to_wstring(-days) + L" 天");
    else line(L"狀態", L"有效，剩餘 " + std::to_wstring(days) + L" 天");
    std::wstring kind = IsCA(c) ? L"CA 憑證" : L"終端實體憑證";
    if (IsSelfSigned(c)) kind += L"（自簽）";
    line(L"類型", kind);
    line(L"簽章演算法", OidName(ci->SignatureAlgorithm.pszObjId));

    std::wstring pk = OidName(ci->SubjectPublicKeyInfo.Algorithm.pszObjId, CRYPT_PUBKEY_ALG_OID_GROUP_ID);
    DWORD bits = CertGetPublicKeyLength(X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)&ci->SubjectPublicKeyInfo);
    if (strcmp(ci->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) == 0) {
        LPSTR* curve = nullptr;
        DWORD cb = 0;
        const auto& prm = ci->SubjectPublicKeyInfo.Algorithm.Parameters;
        if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER, prm.pbData, prm.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &curve, &cb)) {
            pk = L"EC " + OidName(*curve);
            LocalFree(curve);
        }
    }
    line(L"公開金鑰", pk + L" (" + std::to_wstring(bits) + L" bits)");
    line(L"SHA-1 指紋", Thumbprint(c, BCRYPT_SHA1_ALGORITHM));
    line(L"SHA-256 指紋", Thumbprint(c, BCRYPT_SHA256_ALGORITHM));

    if (ci->cExtension) {
        s += L"\r\n── 擴充欄位 ──\r\n";
        for (DWORD i = 0; i < ci->cExtension; i++) {
            const CERT_EXTENSION& e = ci->rgExtension[i];
            s += L"■ " + OidName(e.pszObjId) + (e.fCritical ? L"（重要）" : L"") + L"\r\n";
            DWORD cb = 0;
            if (CryptFormatObject(X509_ASN_ENCODING, 0, CRYPT_FORMAT_STR_MULTI_LINE, nullptr, e.pszObjId, e.Value.pbData, e.Value.cbData, nullptr, &cb) && cb) {
                std::wstring v(cb / sizeof(wchar_t), L'\0');
                CryptFormatObject(X509_ASN_ENCODING, 0, CRYPT_FORMAT_STR_MULTI_LINE, nullptr, e.pszObjId, e.Value.pbData, e.Value.cbData, v.data(), &cb);
                v.resize(wcslen(v.c_str()));
                size_t pos = 0;
                while (pos < v.size()) {
                    size_t nl = v.find(L"\r\n", pos);
                    std::wstring ln = v.substr(pos, nl == std::wstring::npos ? std::wstring::npos : nl - pos);
                    if (!ln.empty()) s += L"    " + ln + L"\r\n";
                    if (nl == std::wstring::npos) break;
                    pos = nl + 2;
                }
            }
        }
    }
    return s;
}

std::wstring TrustErrorText(DWORD st, bool* onlyWarnings) {
    struct { DWORD flag; const wchar_t* text; } table[] = {
        {CERT_TRUST_IS_NOT_TIME_VALID, L"不在有效期間內（已過期或尚未生效）"},
        {CERT_TRUST_IS_REVOKED, L"憑證已被撤銷"},
        {CERT_TRUST_IS_NOT_SIGNATURE_VALID, L"簽章無效"},
        {CERT_TRUST_IS_NOT_VALID_FOR_USAGE, L"不適用於此用途"},
        {CERT_TRUST_IS_UNTRUSTED_ROOT, L"根憑證不受此電腦信任"},
        {CERT_TRUST_IS_CYCLIC, L"憑證鏈有循環"},
        {CERT_TRUST_INVALID_EXTENSION, L"擴充欄位無效"},
        {CERT_TRUST_INVALID_POLICY_CONSTRAINTS, L"原則限制無效"},
        {CERT_TRUST_INVALID_BASIC_CONSTRAINTS, L"基本限制無效（簽發者不是 CA）"},
        {CERT_TRUST_INVALID_NAME_CONSTRAINTS, L"名稱限制無效"},
        {CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT, L"有不支援的名稱限制"},
        {CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT, L"有未定義的名稱限制"},
        {CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT, L"名稱不被允許"},
        {CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT, L"名稱被排除"},
        {CERT_TRUST_IS_PARTIAL_CHAIN, L"憑證鏈不完整（找不到上層簽發者）"},
        {CERT_TRUST_IS_EXPLICIT_DISTRUST, L"已被明確設為不信任"},
        {CERT_TRUST_HAS_WEAK_SIGNATURE, L"使用弱簽章演算法"},
        {CERT_TRUST_REVOCATION_STATUS_UNKNOWN, L"無法確認撤銷狀態"},
        {CERT_TRUST_IS_OFFLINE_REVOCATION, L"撤銷清單伺服器離線"},
    };
    const DWORD warnMask = CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION;
    if (onlyWarnings) *onlyWarnings = (st & ~warnMask) == 0;
    std::wstring s;
    DWORD known = 0;
    for (auto& t : table) {
        if (st & t.flag) {
            if (!s.empty()) s += L"、";
            s += t.text;
            known |= t.flag;
        }
    }
    if (st & ~known) {
        wchar_t buf[32];
        swprintf_s(buf, L"其他錯誤 0x%08X", st & ~known);
        if (!s.empty()) s += L"、";
        s += buf;
    }
    return s;
}

// ============================================================================
// Workspace：載入
// ============================================================================

static bool PromptLoop(const PasswordPrompt& prompt, const std::wstring& what,
                       const std::function<int(const std::wstring&)>& attempt, std::wstring& err) {
    std::wstring msg = what;
    for (;;) {
        std::wstring pwd;
        if (!prompt || !prompt(msg, pwd)) {
            err = L"已取消輸入密碼";
            return false;
        }
        int r = attempt(pwd);
        SecureZeroMemory(pwd.data(), pwd.size() * sizeof(wchar_t));
        if (r == 0) return true;
        if (r == 2) return false;
        msg = L"密碼錯誤，請重新輸入。\n" + what;
    }
}

LoadResult Workspace::LoadFile(const std::wstring& path, const PasswordPrompt& prompt) {
    LoadResult r;
    Bytes data;
    std::wstring name = FileNameOf(path);
    if (!ReadAll(path, data)) {
        r.messages.push_back(name + L"：無法讀取檔案");
        return r;
    }
    // 已簽章的執行檔：取出 Authenticode 簽章中的憑證
    if (data.size() > 2 && data[0] == 'M' && data[1] == 'Z') {
        HCERTSTORE store = nullptr;
        if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                             CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr, &store, nullptr, nullptr)) {
            for (PCCERT_CONTEXT c = nullptr; (c = CertEnumCertificatesInStore(store, c)) != nullptr;) {
                if (AddCert(CertFromDer(c->pbCertEncoded, c->cbCertEncoded), name)) r.certsAdded++;
                else r.certsDuplicated++;
            }
            CertCloseStore(store, 0);
            MatchKeys();
        } else {
            r.messages.push_back(name + L"：執行檔沒有數位簽章");
        }
        return r;
    }
    return LoadBytes(data, name, prompt);
}

LoadResult Workspace::LoadBytes(const Bytes& input, const std::wstring& source, const PasswordPrompt& prompt) {
    LoadResult r;
    Bytes data = input;
    // UTF-16 文字檔 → UTF-8
    if (data.size() >= 2 && data[0] == 0xFF && data[1] == 0xFE) {
        std::wstring w((const wchar_t*)(data.data() + 2), (data.size() - 2) / 2);
        std::string u = ToUtf8(w);
        data.assign(u.begin(), u.end());
    }
    if (data.size() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) data.erase(data.begin(), data.begin() + 3);

    std::string text(data.begin(), data.end());
    if (text.find("-----BEGIN ") != std::string::npos)
        LoadPem(text, source, prompt, r);
    else
        LoadBinary(data, source, prompt, r);
    MatchKeys();
    return r;
}

void Workspace::LoadPem(const std::string& text, const std::wstring& source, const PasswordPrompt& prompt, LoadResult& r) {
    size_t pos = 0;
    while (true) {
        size_t b = text.find("-----BEGIN ", pos);
        if (b == std::string::npos) break;
        size_t le = text.find("-----", b + 11);
        if (le == std::string::npos) break;
        std::string label = text.substr(b + 11, le - (b + 11));
        std::string endMarker = "-----END " + label + "-----";
        size_t e = text.find(endMarker, le + 5);
        if (e == std::string::npos) {
            r.messages.push_back(source + L"：PEM 區塊「" + FromUtf8(label) + L"」沒有結尾");
            break;
        }
        std::string body = text.substr(le + 5, e - (le + 5));
        pos = e + endMarker.size();

        // 拆出標頭（Proc-Type、DEK-Info）與 base64 內容
        std::map<std::string, std::string> headers;
        std::string b64;
        size_t lp = 0;
        while (lp <= body.size()) {
            size_t nl = body.find('\n', lp);
            std::string ln = Trim(body.substr(lp, nl == std::string::npos ? std::string::npos : nl - lp));
            size_t colon = ln.find(':');
            if (colon != std::string::npos) headers[Trim(ln.substr(0, colon))] = Trim(ln.substr(colon + 1));
            else b64 += ln;
            if (nl == std::string::npos) break;
            lp = nl + 1;
        }
        Bytes der = Base64Decode(b64);
        std::wstring wlabel = FromUtf8(label);
        if (der.empty()) {
            r.messages.push_back(source + L"：「" + wlabel + L"」區塊內容不是有效的 Base64");
            continue;
        }

        if (label == "CERTIFICATE" || label == "X509 CERTIFICATE" || label == "TRUSTED CERTIFICATE") {
            Der d;
            CertPtr c = DerParse(der.data(), der.size(), d) ? CertFromDer(d.raw, d.rawLen) : nullptr;
            if (!c) r.messages.push_back(source + L"：有一張憑證無法解析");
            else if (AddCert(c, source)) r.certsAdded++;
            else r.certsDuplicated++;
        } else if (label == "PKCS7" || label == "CMS") {
            bool recognized = false;
            LoadStoreBlob(der, source, r, recognized);
            if (!recognized) r.messages.push_back(source + L"：PKCS#7 內容無法解析");
        } else if (label == "PRIVATE KEY") {
            std::wstring err;
            if (AddKey(der, source, err)) r.keysAdded++;
            else if (!err.empty()) r.messages.push_back(source + L"：" + err);
        } else if (label == "RSA PRIVATE KEY" || label == "EC PRIVATE KEY") {
            Bytes inner = der;
            std::wstring err;
            bool ok = true;
            auto pt = headers.find("Proc-Type");
            if (pt != headers.end() && pt->second.find("ENCRYPTED") != std::string::npos) {
                std::string dek = headers["DEK-Info"];
                ok = PromptLoop(prompt, L"私鑰已加密（" + source + L"），請輸入私鑰密碼：",
                                [&](const std::wstring& pwd) { return DecryptLegacyPem(der, dek, pwd, inner, err); }, err);
            }
            Bytes pkcs8;
            if (ok) {
                if (label == "RSA PRIVATE KEY") {
                    ok = RsaPkcs1ToPkcs8(inner, pkcs8);
                    if (!ok) err = L"RSA 私鑰格式錯誤";
                } else {
                    ok = EcSec1ToPkcs8(inner, pkcs8, err);
                }
            }
            if (ok && AddKey(pkcs8, source, err)) r.keysAdded++;
            else if (!err.empty()) r.messages.push_back(source + L"：" + err);
        } else if (label == "ENCRYPTED PRIVATE KEY") {
            Bytes pkcs8;
            std::wstring err;
            bool ok = PromptLoop(prompt, L"私鑰已加密（" + source + L"），請輸入私鑰密碼：",
                                 [&](const std::wstring& pwd) { return DecryptEncryptedPkcs8(der, pwd, pkcs8, err); }, err);
            if (ok && AddKey(pkcs8, source, err)) r.keysAdded++;
            else if (!err.empty()) r.messages.push_back(source + L"：" + err);
        } else if (label == "CERTIFICATE REQUEST" || label == "NEW CERTIFICATE REQUEST") {
            r.messages.push_back(source + L"：略過 CSR（憑證簽署要求）");
        } else if (label == "X509 CRL") {
            r.messages.push_back(source + L"：略過 CRL（撤銷清單）");
        } else if (label == "EC PARAMETERS") {
            // openssl ecparam -genkey 會附帶，忽略
        } else {
            r.messages.push_back(source + L"：略過不支援的區塊「" + wlabel + L"」");
        }
    }
    if (r.certsAdded + r.certsDuplicated + r.keysAdded == 0 && r.messages.empty())
        r.messages.push_back(source + L"：找不到可用的 PEM 區塊");
}

void Workspace::LoadStoreBlob(const Bytes& data, const std::wstring& source, LoadResult& r, bool& recognized) {
    CERT_BLOB blob = {(DWORD)data.size(), (BYTE*)data.data()};
    HCERTSTORE store = nullptr;
    recognized = false;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                          CERT_QUERY_CONTENT_FLAG_CERT | CERT_QUERY_CONTENT_FLAG_SERIALIZED_CERT |
                              CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
                              CERT_QUERY_CONTENT_FLAG_PKCS7_UNSIGNED,
                          CERT_QUERY_FORMAT_FLAG_ALL, 0, nullptr, nullptr, nullptr, &store, nullptr, nullptr))
        return;
    recognized = true;
    int n = 0;
    for (PCCERT_CONTEXT c = nullptr; (c = CertEnumCertificatesInStore(store, c)) != nullptr;) {
        n++;
        if (AddCert(CertFromDer(c->pbCertEncoded, c->cbCertEncoded), source)) r.certsAdded++;
        else r.certsDuplicated++;
    }
    CertCloseStore(store, 0);
    if (n == 0) r.messages.push_back(source + L"：檔案內沒有憑證");
}

void Workspace::LoadBinary(const Bytes& data, const std::wstring& source, const PasswordPrompt& prompt, LoadResult& r) {
    if (data.empty()) {
        r.messages.push_back(source + L"：空白檔案");
        return;
    }
    // 1) 單張 DER 憑證
    Der d;
    if (DerParse(data.data(), data.size(), d) && d.tag == 0x30 && d.rawLen == data.size()) {
        if (CertPtr c = CertFromDer(data.data(), data.size())) {
            if (AddCert(c, source)) r.certsAdded++;
            else r.certsDuplicated++;
            return;
        }
    }
    // 2) PFX / P12
    CRYPT_DATA_BLOB blob = {(DWORD)data.size(), (BYTE*)data.data()};
    if (PFXIsPFXBlob(&blob)) {
        LoadPfx(data, source, prompt, r);
        return;
    }
    // 3) P7B、序列化存放區、無標頭的 Base64 憑證
    bool recognized = false;
    LoadStoreBlob(data, source, r, recognized);
    if (recognized) return;

    // 4) DER 私鑰
    void* decoded = nullptr;
    DWORD cb = 0;
    std::wstring err;
    if (CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, data.data(), (DWORD)data.size(), CRYPT_DECODE_ALLOC_FLAG, nullptr, &decoded, &cb)) {
        LocalFree(decoded);
        if (AddKey(data, source, err)) r.keysAdded++;
        else if (!err.empty()) r.messages.push_back(source + L"：" + err);
        return;
    }
    if (CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_ENCRYPTED_PRIVATE_KEY_INFO, data.data(), (DWORD)data.size(), CRYPT_DECODE_ALLOC_FLAG, nullptr, &decoded, &cb)) {
        LocalFree(decoded);
        Bytes pkcs8;
        bool ok = PromptLoop(prompt, L"私鑰已加密（" + source + L"），請輸入私鑰密碼：",
                             [&](const std::wstring& pwd) { return DecryptEncryptedPkcs8(data, pwd, pkcs8, err); }, err);
        if (ok && AddKey(pkcs8, source, err)) r.keysAdded++;
        else if (!err.empty()) r.messages.push_back(source + L"：" + err);
        return;
    }
    if (CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, data.data(), (DWORD)data.size(), CRYPT_DECODE_ALLOC_FLAG, nullptr, &decoded, &cb)) {
        LocalFree(decoded);
        Bytes pkcs8;
        if (RsaPkcs1ToPkcs8(data, pkcs8) && AddKey(pkcs8, source, err)) r.keysAdded++;
        else if (!err.empty()) r.messages.push_back(source + L"：" + err);
        return;
    }
    Bytes pkcs8;
    if (EcSec1ToPkcs8(data, pkcs8, err)) {
        if (AddKey(pkcs8, source, err)) r.keysAdded++;
        else if (!err.empty()) r.messages.push_back(source + L"：" + err);
        return;
    }
    r.messages.push_back(source + L"：無法辨識的檔案格式");
}

void Workspace::LoadPfx(const Bytes& data, const std::wstring& source, const PasswordPrompt& prompt, LoadResult& r) {
    CRYPT_DATA_BLOB blob = {(DWORD)data.size(), (BYTE*)data.data()};
    std::wstring pwd;
    bool have = false;
    if (PFXVerifyPassword(&blob, L"", 0)) have = true;
    else if (PFXVerifyPassword(&blob, nullptr, 0)) { have = true; }
    if (!have) {
        std::wstring err;
        if (!PromptLoop(prompt, L"請輸入 PFX 密碼（" + source + L"）：",
                        [&](const std::wstring& p) {
                            if (!PFXVerifyPassword(&blob, p.c_str(), 0)) return 1;
                            pwd = p;
                            return 0;
                        }, err)) {
            r.messages.push_back(source + L"：" + err);
            return;
        }
    }
    const DWORD flags = CRYPT_EXPORTABLE | PKCS12_NO_PERSIST_KEY | PKCS12_ALWAYS_CNG_KSP;
    HCERTSTORE store = PFXImportCertStore(&blob, pwd.c_str(), flags);
    if (!store && pwd.empty()) store = PFXImportCertStore(&blob, nullptr, flags);
    if (!store) {
        r.messages.push_back(source + L"：無法開啟 PFX：" + LastErrorText(GetLastError()));
        SecureZeroMemory(pwd.data(), pwd.size() * sizeof(wchar_t));
        return;
    }
    SecureZeroMemory(pwd.data(), pwd.size() * sizeof(wchar_t));
    for (PCCERT_CONTEXT c = nullptr; (c = CertEnumCertificatesInStore(store, c)) != nullptr;) {
        if (AddCert(CertFromDer(c->pbCertEncoded, c->cbCertEncoded), source)) r.certsAdded++;
        else r.certsDuplicated++;

        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hk = 0;
        DWORD spec = 0;
        BOOL mustFree = FALSE;
        // PKCS12_NO_PERSIST_KEY 的私鑰是以 CERT_KEY_CONTEXT_PROP_ID 暫存在 context 上，須用 CACHE 旗標取得
        if (CryptAcquireCertificatePrivateKey(c, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                                              nullptr, &hk, &spec, &mustFree)) {
            Bytes pkcs8;
            SECURITY_STATUS st = ExportPkcs8FromHandle((NCRYPT_KEY_HANDLE)hk, pkcs8);
            if (mustFree) NCryptFreeObject((NCRYPT_KEY_HANDLE)hk);
            std::wstring err;
            if (st != ERROR_SUCCESS) r.messages.push_back(source + L"：私鑰無法匯出：" + LastErrorText(st));
            else if (AddKey(pkcs8, source, err)) r.keysAdded++;
            else if (!err.empty()) r.messages.push_back(source + L"：" + err);
            SecureZeroMemory(pkcs8.data(), pkcs8.size());
        } else if (GetLastError() != (DWORD)CRYPT_E_NO_KEY_PROPERTY) {
            r.messages.push_back(source + L"：無法讀取私鑰：" + LastErrorText(GetLastError()));
        }
    }
    CertCloseStore(store, 0);
}

// ============================================================================
// Workspace：管理
// ============================================================================

bool Workspace::AddCert(const CertPtr& cert, const std::wstring& source) {
    if (!cert) return false;
    for (auto& it : certs) {
        if (it.cert->cbCertEncoded == cert->cbCertEncoded && memcmp(it.cert->pbCertEncoded, cert->pbCertEncoded, cert->cbCertEncoded) == 0)
            return false;
    }
    certs.push_back({cert, source, -1});
    return true;
}

bool Workspace::AddKey(const Bytes& pkcs8, const std::wstring& source, std::wstring& err) {
    err.clear();
    NCRYPT_KEY_HANDLE h = 0;
    SECURITY_STATUS st = ImportPkcs8(pkcs8, nullptr, &h);
    if (st != ERROR_SUCCESS) {
        err = L"無法讀取私鑰（可能是不支援的演算法）：" + LastErrorText(st);
        return false;
    }
    NcHandle g(h);
    KeyItem k;
    if (!DescribeKeyHandle(h, k, err)) return false;
    for (auto& existing : keys)
        if (existing.publicKeyBits == k.publicKeyBits) return false;   // 重複
    k.pkcs8 = pkcs8;
    k.source = source;
    keys.push_back(std::move(k));
    MatchKeys();
    return true;
}

void Workspace::RemoveCert(int index) {
    if (index < 0 || index >= (int)certs.size()) return;
    if (leafOverride == certs[index].cert.get()) leafOverride = nullptr;
    certs.erase(certs.begin() + index);
    MatchKeys();
}

void Workspace::RemoveKey(int index) {
    if (index < 0 || index >= (int)keys.size()) return;
    SecureZeroMemory(keys[index].pkcs8.data(), keys[index].pkcs8.size());
    keys.erase(keys.begin() + index);
    MatchKeys();
}

void Workspace::Clear() {
    for (auto& k : keys) SecureZeroMemory(k.pkcs8.data(), k.pkcs8.size());
    certs.clear();
    keys.clear();
    leafOverride = nullptr;
}

void Workspace::MatchKeys() {
    for (auto& c : certs) {
        c.keyIndex = -1;
        const CERT_PUBLIC_KEY_INFO& spki = c.cert->pCertInfo->SubjectPublicKeyInfo;
        for (size_t k = 0; k < keys.size(); k++) {
            const Bytes& bits = keys[k].publicKeyBits;
            bool eq = spki.PublicKey.cbData == bits.size() && memcmp(spki.PublicKey.pbData, bits.data(), bits.size()) == 0;
            if (!eq) {
                CERT_PUBLIC_KEY_INFO ki = spki;
                ki.PublicKey.pbData = (BYTE*)bits.data();
                ki.PublicKey.cbData = (DWORD)bits.size();
                ki.PublicKey.cUnusedBits = 0;
                eq = CertComparePublicKeyInfo(X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)&spki, &ki) != FALSE;
            }
            if (eq) {
                c.keyIndex = (int)k;
                break;
            }
        }
    }
}

std::vector<int> Workspace::UnmatchedKeys() const {
    std::vector<int> out;
    for (int k = 0; k < (int)keys.size(); k++) {
        bool used = std::any_of(certs.begin(), certs.end(), [k](const CertItem& c) { return c.keyIndex == k; });
        if (!used) out.push_back(k);
    }
    return out;
}

int Workspace::FindCert(const CERT_CONTEXT* ctx) const {
    for (int i = 0; i < (int)certs.size(); i++)
        if (certs[i].cert.get() == ctx) return i;
    return -1;
}

std::vector<OrderEntry> Workspace::BuildOrder() const {
    const int n = (int)certs.size();
    std::vector<OrderEntry> out;
    if (n == 0) return out;

    std::vector<char> self(n), usedAsIssuer(n);
    std::vector<int> issuer(n, -1);
    for (int i = 0; i < n; i++) self[i] = IsSelfSigned(certs[i].cert.get());
    for (int i = 0; i < n; i++) {
        if (self[i]) continue;
        int best = -1, bestScore = -1;
        for (int j = 0; j < n; j++) {
            if (j == i || !IsIssuerOf(certs[j].cert.get(), certs[i].cert.get())) continue;
            // 多個候選（例如交叉簽署）時：優先未過期，其次自簽根憑證
            int score = (DaysRemaining(certs[j].cert.get()) >= 0 ? 2 : 0) + (self[j] ? 1 : 0);
            if (score > bestScore) { best = j; bestScore = score; }
        }
        issuer[i] = best;
        if (best >= 0) usedAsIssuer[best] = 1;
    }
    auto chainLen = [&](int i) {
        int len = 0;
        std::vector<char> seen(n);
        while (i >= 0 && !seen[i]) { seen[i] = 1; len++; i = issuer[i]; }
        return len;
    };

    int leaf = leafOverride ? FindCert(leafOverride) : -1;
    if (leaf < 0) {
        int bestScore = -1;
        for (int i = 0; i < n; i++) {
            if (usedAsIssuer[i]) continue;
            int score = (certs[i].keyIndex >= 0 ? 10000 : 0) + chainLen(i) * 10 + (!IsCA(certs[i].cert.get()) ? 5 : 0) + (!self[i] ? 1 : 0);
            if (score > bestScore) { bestScore = score; leaf = i; }
        }
        if (leaf < 0) {
            for (int i = 0; i < n; i++)
                if (leaf < 0 || chainLen(i) > chainLen(leaf)) leaf = i;
        }
    }

    std::vector<char> inChain(n);
    for (int i = leaf; i >= 0 && !inChain[i]; i = issuer[i]) {
        inChain[i] = 1;
        out.push_back({i, Role::Intermediate, false});
    }
    out.front().role = Role::Leaf;
    OrderEntry& last = out.back();
    if (self[last.certIndex]) {
        if (out.size() > 1 || IsCA(certs[last.certIndex].cert.get())) last.role = Role::Root;
    } else {
        last.issuerMissing = true;
    }
    for (int i = 0; i < n; i++)
        if (!inChain[i]) out.push_back({i, Role::Unused, false});
    return out;
}

// ============================================================================
// 驗證
// ============================================================================

ChainReport BuildSystemChain(const CertPtr& leaf, const std::vector<CertPtr>& extra, bool checkRevocation) {
    ChainReport r;
    HCERTSTORE mem = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
    for (auto& c : extra) CertAddCertificateContextToStore(mem, c.get(), CERT_STORE_ADD_USE_EXISTING, nullptr);

    CERT_CHAIN_PARA para = {};
    para.cbSize = sizeof(para);
    para.dwUrlRetrievalTimeout = 15000;
    DWORD flags = checkRevocation ? CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT : 0;
    PCCERT_CHAIN_CONTEXT chain = nullptr;
    if (!CertGetCertificateChain(nullptr, leaf.get(), nullptr, mem, &para, flags, nullptr, &chain)) {
        r.error = LastErrorText(GetLastError());
    } else {
        r.ok = true;
        r.errorStatus = chain->TrustStatus.dwErrorStatus;
        if (chain->cChain > 0) {
            PCERT_SIMPLE_CHAIN sc = chain->rgpChain[0];
            for (DWORD i = 0; i < sc->cElement; i++) {
                PCCERT_CONTEXT c = sc->rgpElement[i]->pCertContext;
                r.elements.push_back(CertFromDer(c->pbCertEncoded, c->cbCertEncoded));
                r.elementErrors.push_back(sc->rgpElement[i]->TrustStatus.dwErrorStatus);
            }
        }
        CertFreeCertificateChain(chain);
    }
    CertCloseStore(mem, 0);
    return r;
}

// ============================================================================
// 匯出
// ============================================================================

std::string CertToPem(PCCERT_CONTEXT c) { return PemBlock("CERTIFICATE", c->pbCertEncoded, c->cbCertEncoded); }

std::string KeyToPem(const Bytes& pkcs8) { return PemBlock("PRIVATE KEY", pkcs8.data(), pkcs8.size()); }

bool KeyToPkcs1Pem(const Bytes& pkcs8, std::string& out, std::wstring& err) {
    CRYPT_PRIVATE_KEY_INFO* pki = nullptr;
    DWORD cb = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, pkcs8.data(), (DWORD)pkcs8.size(), CRYPT_DECODE_ALLOC_FLAG, nullptr, &pki, &cb)) {
        err = L"私鑰格式錯誤";
        return false;
    }
    bool ok = strcmp(pki->Algorithm.pszObjId, szOID_RSA_RSA) == 0;
    if (ok) out = PemBlock("RSA PRIVATE KEY", pki->PrivateKey.pbData, pki->PrivateKey.cbData);
    else err = L"只有 RSA 私鑰可以輸出成傳統 PKCS#1 格式";
    LocalFree(pki);
    return ok;
}

bool ExportP7b(const std::vector<CertPtr>& certs, Bytes& out, std::wstring& err) {
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
    for (auto& c : certs) CertAddCertificateContextToStore(store, c.get(), CERT_STORE_ADD_ALWAYS, nullptr);
    CERT_BLOB blob = {};
    bool ok = CertSaveStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_MEMORY, &blob, 0) != FALSE;
    if (ok) {
        out.resize(blob.cbData);
        blob.pbData = out.data();
        ok = CertSaveStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_MEMORY, &blob, 0) != FALSE;
        out.resize(blob.cbData);
    }
    if (!ok) err = LastErrorText(GetLastError());
    CertCloseStore(store, 0);
    return ok;
}

bool ExportPfx(const std::vector<CertPtr>& chain, const KeyItem* leafKey, const std::wstring& password, bool aes256, Bytes& out, std::wstring& err) {
    if (chain.empty()) {
        err = L"沒有憑證可以匯出";
        return false;
    }
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
    bool ok = true;
    PCCERT_CONTEXT leafInStore = nullptr;
    for (size_t i = 0; i < chain.size() && ok; i++) {
        PCCERT_CONTEXT added = nullptr;
        ok = CertAddCertificateContextToStore(store, chain[i].get(), CERT_STORE_ADD_ALWAYS, i == 0 ? &added : nullptr) != FALSE;
        if (i == 0) leafInStore = added;
    }
    if (!ok) err = LastErrorText(GetLastError());

    if (ok && leafInStore) {
        std::wstring fn = CertDisplayName(leafInStore);
        CRYPT_DATA_BLOB nameBlob = {(DWORD)((fn.size() + 1) * sizeof(wchar_t)), (BYTE*)fn.c_str()};
        CertSetCertificateContextProperty(leafInStore, CERT_FRIENDLY_NAME_PROP_ID, 0, &nameBlob);
    }
    if (ok && leafKey && leafInStore) {
        NCRYPT_KEY_HANDLE h = 0;
        SECURITY_STATUS st = ImportPkcs8(leafKey->pkcs8, nullptr, &h);
        if (st != ERROR_SUCCESS) {
            err = L"無法載入私鑰：" + LastErrorText(st);
            ok = false;
        } else if (!CertSetCertificateContextProperty(leafInStore, CERT_NCRYPT_KEY_HANDLE_PROP_ID, CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG, (const void*)h)) {
            err = L"無法將私鑰附加到憑證：" + LastErrorText(GetLastError());
            NCryptFreeObject(h);
            ok = false;
        }
        // 成功時金鑰 handle 由憑證 context 持有，關閉存放區時一併釋放
    }
    if (leafInStore) CertFreeCertificateContext(leafInStore);

    if (ok) {
        DWORD flags = leafKey ? (EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY) : 0;
        PKCS12_PBES2_EXPORT_PARAMS pbes2 = {sizeof(pbes2), nullptr, (LPWSTR)PKCS12_PBES2_ALG_AES256_SHA256};
        void* pvPara = nullptr;
        if (aes256) {
            flags |= PKCS12_EXPORT_PBES2_PARAMS;
            pvPara = &pbes2;
        }
        CRYPT_DATA_BLOB blob = {};
        ok = PFXExportCertStoreEx(store, &blob, password.c_str(), pvPara, flags) != FALSE;
        if (ok) {
            out.resize(blob.cbData);
            blob.pbData = out.data();
            ok = PFXExportCertStoreEx(store, &blob, password.c_str(), pvPara, flags) != FALSE;
            out.resize(blob.cbData);
        }
        if (!ok) err = L"PFX 匯出失敗：" + LastErrorText(GetLastError());
    }
    CertCloseStore(store, 0);
    return ok;
}

// ============================================================================
// CSR / 私鑰產生
// ============================================================================

static void DerAppendLen(Bytes& o, size_t n) {
    if (n < 0x80) {
        o.push_back((BYTE)n);
        return;
    }
    BYTE tmp[8];
    int k = 0;
    while (n) { tmp[k++] = (BYTE)(n & 0xFF); n >>= 8; }
    o.push_back((BYTE)(0x80 | k));
    while (k) o.push_back(tmp[--k]);
}

static Bytes DerTlv(BYTE tag, const Bytes& content) {
    Bytes o{tag};
    DerAppendLen(o, content.size());
    o.insert(o.end(), content.begin(), content.end());
    return o;
}

static Bytes DerSeq(std::initializer_list<Bytes> parts) {
    Bytes c;
    for (auto& p : parts) c.insert(c.end(), p.begin(), p.end());
    return DerTlv(0x30, c);
}

static Bytes DerOid(std::initializer_list<BYTE> oid) { return DerTlv(0x06, Bytes(oid)); }

static Bytes DerInteger(unsigned long v) {
    Bytes c;
    do { c.insert(c.begin(), (BYTE)(v & 0xFF)); v >>= 8; } while (v);
    if (c[0] & 0x80) c.insert(c.begin(), 0);
    return DerTlv(0x02, c);
}

static bool SymEncrypt(LPCWSTR alg, const Bytes& key, const Bytes& iv, const Bytes& data, Bytes& out) {
    BCRYPT_ALG_HANDLE a = nullptr;
    BCRYPT_KEY_HANDLE k = nullptr;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&a, alg, nullptr, 0)) &&
        BCRYPT_SUCCESS(BCryptSetProperty(a, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) &&
        BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(a, &k, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0))) {
        Bytes ivc = iv;
        ULONG cb = 0;
        if (BCRYPT_SUCCESS(BCryptEncrypt(k, (PUCHAR)data.data(), (ULONG)data.size(), nullptr, ivc.data(), (ULONG)ivc.size(), nullptr, 0, &cb, BCRYPT_BLOCK_PADDING))) {
            out.resize(cb);
            ivc = iv;
            ok = BCRYPT_SUCCESS(BCryptEncrypt(k, (PUCHAR)data.data(), (ULONG)data.size(), nullptr, ivc.data(), (ULONG)ivc.size(), out.data(), cb, &cb, BCRYPT_BLOCK_PADDING));
            out.resize(cb);
        }
    }
    if (k) BCryptDestroyKey(k);
    if (a) BCryptCloseAlgorithmProvider(a, 0);
    return ok;
}

bool KeyToEncryptedPem(const Bytes& pkcs8, const std::wstring& password, std::string& out, std::wstring& err) {
    if (password.empty()) {
        err = L"請輸入密碼";
        return false;
    }
    const unsigned long iter = 100000;
    Bytes salt(16), iv(16), key(32);
    BCryptGenRandom(nullptr, salt.data(), (ULONG)salt.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(nullptr, iv.data(), (ULONG)iv.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::string pwd = ToUtf8(password);
    BCRYPT_ALG_HANDLE hPrf = nullptr;
    bool ok = BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hPrf, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)) &&
              BCRYPT_SUCCESS(BCryptDeriveKeyPBKDF2(hPrf, (PUCHAR)pwd.data(), (ULONG)pwd.size(), salt.data(), (ULONG)salt.size(), iter, key.data(), (ULONG)key.size(), 0));
    if (hPrf) BCryptCloseAlgorithmProvider(hPrf, 0);
    SecureZeroMemory(pwd.data(), pwd.size());
    Bytes enc;
    if (!ok || !SymEncrypt(BCRYPT_AES_ALGORITHM, key, iv, pkcs8, enc)) {
        err = L"私鑰加密失敗";
        return false;
    }
    SecureZeroMemory(key.data(), key.size());
    Bytes params = DerSeq({
        DerSeq({DerOid({0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C}),            // PBKDF2
                DerSeq({DerTlv(0x04, salt), DerInteger(iter),
                        DerSeq({DerOid({0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09}), DerTlv(0x05, Bytes())})})}),   // hmacWithSHA256
        DerSeq({DerOid({0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A}), DerTlv(0x04, iv)}),   // aes256-CBC
    });
    Bytes epki = DerSeq({DerSeq({DerOid({0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D}), params}), DerTlv(0x04, enc)});   // PBES2
    out = PemBlock("ENCRYPTED PRIVATE KEY", epki.data(), epki.size());
    return true;
}

std::string CsrToPem(const Bytes& csrDer) { return PemBlock("CERTIFICATE REQUEST", csrDer.data(), csrDer.size()); }

static bool EncodeObj(LPCSTR type, const void* s, Bytes& out) {
    BYTE* p = nullptr;
    DWORD cb = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, type, s, CRYPT_ENCODE_ALLOC_FLAG, nullptr, &p, &cb)) return false;
    out.assign(p, p + cb);
    LocalFree(p);
    return true;
}

static SECURITY_STATUS GenerateKey(KeyType t, NCRYPT_KEY_HANDLE* out) {
    *out = 0;
    NCRYPT_PROV_HANDLE prov = 0;
    SECURITY_STATUS st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (st != ERROR_SUCCESS) return st;
    NcHandle provGuard(prov);
    LPCWSTR alg = t == KeyType::EcP256 ? BCRYPT_ECDSA_P256_ALGORITHM : t == KeyType::EcP384 ? BCRYPT_ECDSA_P384_ALGORITHM : BCRYPT_RSA_ALGORITHM;
    NCRYPT_KEY_HANDLE h = 0;
    st = NCryptCreatePersistedKey(prov, &h, alg, nullptr, 0, 0);   // 無名稱 = 暫時性金鑰，不寫入磁碟
    if (st != ERROR_SUCCESS) return st;
    if (t == KeyType::Rsa2048 || t == KeyType::Rsa3072 || t == KeyType::Rsa4096) {
        DWORD bits = t == KeyType::Rsa4096 ? 4096 : t == KeyType::Rsa3072 ? 3072 : 2048;
        st = NCryptSetProperty(h, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof(bits), 0);
    }
    DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    if (st == ERROR_SUCCESS) st = NCryptSetProperty(h, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&policy, sizeof(policy), NCRYPT_PERSIST_FLAG);
    if (st == ERROR_SUCCESS) st = NCryptFinalizeKey(h, 0);
    if (st != ERROR_SUCCESS) {
        NCryptFreeObject(h);
        return st;
    }
    *out = h;
    return ERROR_SUCCESS;
}

// 匯入的 EC 私鑰可能被 CNG 當成 ECDH 金鑰而無法簽章，轉成 ECDSA 金鑰
static SECURITY_STATUS EnsureSigningKey(NCRYPT_KEY_HANDLE& h) {
    wchar_t alg[64] = {};
    DWORD cb = 0;
    NCryptGetProperty(h, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)alg, sizeof(alg) - sizeof(wchar_t), &cb, 0);
    if (wcsncmp(alg, L"ECDH", 4) != 0) return ERROR_SUCCESS;
    SECURITY_STATUS st = NCryptExportKey(h, 0, BCRYPT_ECCPRIVATE_BLOB, nullptr, nullptr, 0, &cb, 0);
    if (st != ERROR_SUCCESS) return st;
    Bytes blob(cb);
    st = NCryptExportKey(h, 0, BCRYPT_ECCPRIVATE_BLOB, nullptr, blob.data(), cb, &cb, 0);
    if (st != ERROR_SUCCESS) return st;
    auto* hdr = (BCRYPT_ECCKEY_BLOB*)blob.data();
    if (hdr->dwMagic == BCRYPT_ECDH_PRIVATE_P256_MAGIC) hdr->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
    else if (hdr->dwMagic == BCRYPT_ECDH_PRIVATE_P384_MAGIC) hdr->dwMagic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
    else if (hdr->dwMagic == BCRYPT_ECDH_PRIVATE_P521_MAGIC) hdr->dwMagic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
    else if (hdr->dwMagic == BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC) hdr->dwMagic = BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC;
    NCRYPT_PROV_HANDLE prov = 0;
    st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (st != ERROR_SUCCESS) return st;
    NcHandle provGuard(prov);
    NCRYPT_KEY_HANDLE h2 = 0;
    st = NCryptImportKey(prov, 0, BCRYPT_ECCPRIVATE_BLOB, nullptr, &h2, blob.data(), (DWORD)blob.size(), 0);
    SecureZeroMemory(blob.data(), blob.size());
    if (st != ERROR_SUCCESS) return st;
    NCryptFreeObject(h);
    h = h2;
    return ERROR_SUCCESS;
}

static std::wstring TrimW(const std::wstring& s) {
    size_t b = s.find_first_not_of(L" \t\r\n");
    if (b == std::wstring::npos) return {};
    size_t e = s.find_last_not_of(L" \t\r\n");
    return s.substr(b, e - b + 1);
}

// days <= 0：產生 CSR；days > 0：產生有效 days 天的自簽憑證
static bool GenerateImpl(const CsrRequest& req, int days, Bytes& outDer, Bytes& keyPkcs8, std::wstring& err) {
    if (days > 36500) {
        err = L"有效天數太長（最多 36500 天）";
        return false;
    }
    std::wstring cn = TrimW(req.cn), c = TrimW(req.c);
    if (cn.empty()) {
        err = L"一般名稱（CN）為必填";
        return false;
    }
    for (auto& ch : c) ch = (wchar_t)towupper(ch);
    if (!c.empty() && (c.size() != 2 || !iswalpha(c[0]) || !iswalpha(c[1]))) {
        err = L"國家代碼（C）必須是 2 個英文字母，例如 TW";
        return false;
    }

    // ---- SAN ----
    struct San { bool ip; std::wstring dns; Bytes addr; };
    std::vector<San> sans;
    for (auto raw : req.sans) {
        std::wstring s = TrimW(raw);
        if (s.empty()) continue;
        bool forceIp = false;
        if (_wcsnicmp(s.c_str(), L"DNS:", 4) == 0) s = TrimW(s.substr(4));
        else if (_wcsnicmp(s.c_str(), L"IP:", 3) == 0) { s = TrimW(s.substr(3)); forceIp = true; }
        San san{};
        BYTE a6[16];
        std::string as = ToUtf8(s);
        // 只接受純 IPv4 / IPv6 文字
        unsigned b1, b2, b3, b4;
        char tail;
        if (sscanf_s(as.c_str(), "%u.%u.%u.%u%c", &b1, &b2, &b3, &b4, &tail, 1) == 4 && b1 < 256 && b2 < 256 && b3 < 256 && b4 < 256) {
            san.ip = true;
            san.addr = {(BYTE)b1, (BYTE)b2, (BYTE)b3, (BYTE)b4};
        } else if (s.find(L':') != std::wstring::npos) {
            // IPv6：交給系統解析
            using Fn = LONG(WINAPI*)(PCWSTR, PCWSTR*, void*);
            static Fn parse = (Fn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlIpv6StringToAddressW");
            PCWSTR term = nullptr;
            if (parse && parse(s.c_str(), &term, a6) == 0 && term && *term == 0) {
                san.ip = true;
                san.addr.assign(a6, a6 + 16);
            }
        }
        if (!san.ip) {
            if (forceIp) { err = L"不是有效的 IP 位址：" + s; return false; }
            for (wchar_t ch : s) {
                if (!(iswalnum(ch) && ch < 128) && ch != L'-' && ch != L'.' && ch != L'*' && ch != L'_') {
                    err = L"主體別名含有不允許的字元：" + s + L"\n（中文網域請先轉成 xn-- 開頭的 Punycode）";
                    return false;
                }
            }
            for (auto& ch : s) ch = (wchar_t)towlower(ch);
            san.dns = s;
        }
        bool dup = std::any_of(sans.begin(), sans.end(), [&](const San& x) { return x.ip == san.ip && x.dns == san.dns && x.addr == san.addr; });
        if (!dup) sans.push_back(san);
    }

    // ---- 金鑰 ----
    NCRYPT_KEY_HANDLE h = 0;
    SECURITY_STATUS st = req.existingKey ? ImportPkcs8(*req.existingKey, nullptr, &h) : GenerateKey(req.keyType, &h);
    if (st == ERROR_SUCCESS && req.existingKey) st = EnsureSigningKey(h);
    if (st != ERROR_SUCCESS) {
        if (h) NCryptFreeObject(h);
        err = (req.existingKey ? L"無法使用這把私鑰：" : L"無法產生私鑰：") + LastErrorText(st);
        return false;
    }
    NcHandle keyGuard(h);
    if (req.existingKey) keyPkcs8 = *req.existingKey;
    else if ((st = ExportPlain(h, keyPkcs8)) != ERROR_SUCCESS) {
        err = L"無法匯出新產生的私鑰：" + LastErrorText(st);
        return false;
    }

    DWORD cbInfo = 0;
    if (!CryptExportPublicKeyInfo(h, 0, X509_ASN_ENCODING, nullptr, &cbInfo)) {
        err = L"無法取得公鑰：" + LastErrorText(GetLastError());
        return false;
    }
    Bytes infoBuf(cbInfo);
    auto pInfo = (PCERT_PUBLIC_KEY_INFO)infoBuf.data();
    CryptExportPublicKeyInfo(h, 0, X509_ASN_ENCODING, pInfo, &cbInfo);
    bool isRsa = strcmp(pInfo->Algorithm.pszObjId, szOID_RSA_RSA) == 0;
    DWORD bits = 0, cb = 0;
    NCryptGetProperty(h, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof(bits), &cb, 0);

    // ---- 主體 ----
    std::wstring o = TrimW(req.o), ou = TrimW(req.ou), l = TrimW(req.l), stv = TrimW(req.st), email = TrimW(req.email);
    std::vector<CERT_RDN_ATTR> attrs;
    attrs.reserve(8);
    auto add = [&](LPCSTR oid, DWORD type, const std::wstring& v) {
        if (!v.empty()) attrs.push_back({(LPSTR)oid, type, {0, (BYTE*)v.c_str()}});
    };
    add(szOID_COUNTRY_NAME, CERT_RDN_PRINTABLE_STRING, c);
    add(szOID_STATE_OR_PROVINCE_NAME, CERT_RDN_UTF8_STRING, stv);
    add(szOID_LOCALITY_NAME, CERT_RDN_UTF8_STRING, l);
    add(szOID_ORGANIZATION_NAME, CERT_RDN_UTF8_STRING, o);
    add(szOID_ORGANIZATIONAL_UNIT_NAME, CERT_RDN_UTF8_STRING, ou);
    add(szOID_COMMON_NAME, CERT_RDN_UTF8_STRING, cn);
    add(szOID_RSA_emailAddr, CERT_RDN_IA5_STRING, email);
    std::vector<CERT_RDN> rdns;
    for (auto& a : attrs) rdns.push_back({1, &a});
    CERT_NAME_INFO ni = {(DWORD)rdns.size(), rdns.data()};
    Bytes subject;
    if (!EncodeObj(X509_UNICODE_NAME, &ni, subject)) {
        err = L"主體欄位含有不允許的字元（電子郵件只能用英數字）";
        return false;
    }

    // ---- 擴充欄位 ----
    std::vector<CERT_ALT_NAME_ENTRY> alt;
    for (auto& s : sans) {
        CERT_ALT_NAME_ENTRY e = {};
        if (s.ip) {
            e.dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
            e.IPAddress.cbData = (DWORD)s.addr.size();
            e.IPAddress.pbData = s.addr.data();
        } else {
            e.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
            e.pwszDNSName = (LPWSTR)s.dns.c_str();
        }
        alt.push_back(e);
    }
    CERT_ALT_NAME_INFO ani = {(DWORD)alt.size(), alt.data()};
    Bytes sanBlob, kuBlob, ekuBlob, extBlob;
    BYTE ku = isRsa ? (CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE) : CERT_DIGITAL_SIGNATURE_KEY_USAGE;
    CRYPT_BIT_BLOB kub = {1, &ku, 0};
    LPSTR ekuOids[] = {(LPSTR)szOID_PKIX_KP_SERVER_AUTH};
    CERT_ENHKEY_USAGE eku = {1, ekuOids};
    std::vector<CERT_EXTENSION> exts;
    if (!alt.empty()) {
        if (!EncodeObj(X509_ALTERNATE_NAME, &ani, sanBlob)) { err = L"主體別名編碼失敗"; return false; }
        exts.push_back({(LPSTR)szOID_SUBJECT_ALT_NAME2, FALSE, {(DWORD)sanBlob.size(), sanBlob.data()}});
    }
    EncodeObj(X509_KEY_USAGE, &kub, kuBlob);
    exts.push_back({(LPSTR)szOID_KEY_USAGE, TRUE, {(DWORD)kuBlob.size(), kuBlob.data()}});
    EncodeObj(X509_ENHANCED_KEY_USAGE, &eku, ekuBlob);
    exts.push_back({(LPSTR)szOID_ENHANCED_KEY_USAGE, FALSE, {(DWORD)ekuBlob.size(), ekuBlob.data()}});

    // 自簽憑證另外加上 Basic Constraints（非 CA）、主體與授權金鑰識別碼
    Bytes bcBlob, skiBlob, akiBlob, keyId;
    if (days > 0) {
        CERT_BASIC_CONSTRAINTS2_INFO bc = {FALSE, FALSE, 0};
        EncodeObj(X509_BASIC_CONSTRAINTS2, &bc, bcBlob);
        exts.push_back({(LPSTR)szOID_BASIC_CONSTRAINTS2, TRUE, {(DWORD)bcBlob.size(), bcBlob.data()}});
        HashData(BCRYPT_SHA1_ALGORITHM, Bytes(pInfo->PublicKey.pbData, pInfo->PublicKey.pbData + pInfo->PublicKey.cbData), keyId);
        CRYPT_DATA_BLOB kid = {(DWORD)keyId.size(), keyId.data()};
        EncodeObj(X509_OCTET_STRING, &kid, skiBlob);
        exts.push_back({(LPSTR)szOID_SUBJECT_KEY_IDENTIFIER, FALSE, {(DWORD)skiBlob.size(), skiBlob.data()}});
        CERT_AUTHORITY_KEY_ID2_INFO aki = {};
        aki.KeyId = kid;
        EncodeObj(X509_AUTHORITY_KEY_ID2, &aki, akiBlob);
        exts.push_back({(LPSTR)szOID_AUTHORITY_KEY_IDENTIFIER2, FALSE, {(DWORD)akiBlob.size(), akiBlob.data()}});
    }

    static BYTE nullParams[] = {0x05, 0x00};
    CRYPT_ALGORITHM_IDENTIFIER sig = {};
    if (isRsa) {
        sig.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
        sig.Parameters = {sizeof(nullParams), nullParams};
    } else {
        sig.pszObjId = (LPSTR)(bits >= 384 ? szOID_ECDSA_SHA384 : szOID_ECDSA_SHA256);
    }

    CERT_EXTENSIONS ce = {(DWORD)exts.size(), exts.data()};
    CRYPT_ATTR_BLOB ab = {};
    CRYPT_ATTRIBUTE attr = {(LPSTR)szOID_RSA_certExtensions, 1, &ab};
    CERT_REQUEST_INFO ri = {};
    CERT_INFO ci = {};
    BYTE serial[16];
    LPCSTR structType;
    const void* toBeSigned;
    if (days <= 0) {
        EncodeObj(X509_EXTENSIONS, &ce, extBlob);
        ab = {(DWORD)extBlob.size(), extBlob.data()};
        ri.dwVersion = CERT_REQUEST_V1;
        ri.Subject = {(DWORD)subject.size(), subject.data()};
        ri.SubjectPublicKeyInfo = *pInfo;
        ri.cAttribute = 1;
        ri.rgAttribute = &attr;
        structType = X509_CERT_REQUEST_TO_BE_SIGNED;
        toBeSigned = &ri;
    } else {
        // 序號：16 bytes 隨機正整數（CryptoAPI 的整數是 little-endian，最後一個 byte 是最高位）
        BCryptGenRandom(nullptr, serial, sizeof(serial), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        serial[15] = (BYTE)((serial[15] & 0x7F) | 0x40);
        ULONGLONG now = NowU64();
        ULONGLONG nb = now - 5ULL * 60 * 10000000;                  // 提前 5 分鐘，容忍時鐘誤差
        ULONGLONG na = now + (ULONGLONG)days * 24 * 3600 * 10000000;
        ci.dwVersion = CERT_V3;
        ci.SerialNumber = {sizeof(serial), serial};
        ci.SignatureAlgorithm = sig;
        ci.Issuer = {(DWORD)subject.size(), subject.data()};
        ci.Subject = ci.Issuer;
        ci.NotBefore = {(DWORD)nb, (DWORD)(nb >> 32)};
        ci.NotAfter = {(DWORD)na, (DWORD)(na >> 32)};
        ci.SubjectPublicKeyInfo = *pInfo;
        ci.cExtension = ce.cExtension;
        ci.rgExtension = ce.rgExtension;
        structType = X509_CERT_TO_BE_SIGNED;
        toBeSigned = &ci;
    }
    const wchar_t* what = days > 0 ? L"憑證簽章失敗：" : L"CSR 簽章失敗：";
    cb = 0;
    if (!CryptSignAndEncodeCertificate(h, CERT_NCRYPT_KEY_SPEC, X509_ASN_ENCODING, structType, toBeSigned, &sig, nullptr, nullptr, &cb)) {
        err = what + LastErrorText(GetLastError());
        return false;
    }
    outDer.resize(cb);
    if (!CryptSignAndEncodeCertificate(h, CERT_NCRYPT_KEY_SPEC, X509_ASN_ENCODING, structType, toBeSigned, &sig, nullptr, outDer.data(), &cb)) {
        err = what + LastErrorText(GetLastError());
        return false;
    }
    outDer.resize(cb);
    return true;
}

bool GenerateCsr(const CsrRequest& req, Bytes& csrDer, Bytes& keyPkcs8, std::wstring& err) {
    return GenerateImpl(req, 0, csrDer, keyPkcs8, err);
}

bool GenerateSelfSigned(const CsrRequest& req, int days, Bytes& certDer, Bytes& keyPkcs8, std::wstring& err) {
    if (days <= 0) {
        err = L"有效天數必須大於 0";
        return false;
    }
    return GenerateImpl(req, days, certDer, keyPkcs8, err);
}

// ============================================================================
// Java KeyStore（JKS）
// ============================================================================
// 格式參考 OpenJDK sun.security.provider.JavaKeyStore / KeyProtector：
//   FEEDFEED, version 2, 項目數, 各項目..., SHA-1(密碼 UTF-16BE + "Mighty Aphrodite" + 前面全部)
//   私鑰以 SHA-1 串流 XOR 保護：salt(20) + 密文 + SHA-1(密碼 + 明文)

static void PutU16(Bytes& o, unsigned v) { o.push_back((BYTE)(v >> 8)); o.push_back((BYTE)v); }
static void PutU32(Bytes& o, unsigned long v) { for (int s = 24; s >= 0; s -= 8) o.push_back((BYTE)(v >> s)); }
static void PutU64(Bytes& o, ULONGLONG v) { for (int s = 56; s >= 0; s -= 8) o.push_back((BYTE)(v >> s)); }
static void PutUtf(Bytes& o, const std::string& s) { PutU16(o, (unsigned)s.size()); o.insert(o.end(), s.begin(), s.end()); }
static void PutBytes(Bytes& o, const BYTE* p, size_t n) { PutU32(o, (unsigned long)n); o.insert(o.end(), p, p + n); }

static std::string JksAlias(const std::wstring& s) {
    std::string a;
    for (wchar_t ch : s) {
        if (ch < 128 && (iswalnum(ch) || ch == L'-' || ch == L'.' || ch == L'_')) a += (char)towlower(ch);
        else if (!a.empty() && a.back() != '-') a += '-';
    }
    while (!a.empty() && a.back() == '-') a.pop_back();
    return a.empty() ? "cert" : a;
}

bool ExportJks(const std::vector<CertPtr>& chain, const KeyItem* leafKey, const std::wstring& password,
               const std::wstring& alias, Bytes& out, std::wstring& err) {
    if (chain.empty()) { err = L"沒有憑證可以匯出"; return false; }
    if (password.size() < 6) { err = L"Java KeyStore 的密碼至少要 6 個字元（keytool 的限制）"; return false; }
    Bytes pw;
    for (wchar_t ch : password) PutU16(pw, ch);   // Java char[] 為 UTF-16，每個字元 big-endian 2 bytes

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULONGLONG ms = (FtToU64(ft) - 116444736000000000ULL) / 10000;

    Bytes body;
    PutU32(body, 0xFEEDFEEDUL);
    PutU32(body, 2);
    bool ok = true;
    if (leafKey) {
        PutU32(body, 1);
        // ---- 私鑰保護 ----
        const Bytes& plain = leafKey->pkcs8;
        Bytes salt(20), digest, enc(plain.size()), check;
        BCryptGenRandom(nullptr, salt.data(), (ULONG)salt.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        digest = salt;
        for (size_t off = 0; ok && off < plain.size(); off += 20) {
            Bytes in = pw;
            in.insert(in.end(), digest.begin(), digest.end());
            ok = HashData(BCRYPT_SHA1_ALGORITHM, in, digest);
            for (size_t j = 0; ok && j < 20 && off + j < plain.size(); j++) enc[off + j] = plain[off + j] ^ digest[j];
        }
        Bytes in = pw;
        in.insert(in.end(), plain.begin(), plain.end());
        ok = ok && HashData(BCRYPT_SHA1_ALGORITHM, in, check);
        SecureZeroMemory(in.data(), in.size());
        Bytes prot = salt;
        prot.insert(prot.end(), enc.begin(), enc.end());
        prot.insert(prot.end(), check.begin(), check.end());
        Bytes epki = DerSeq({DerSeq({DerOid({0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x11, 0x01, 0x01}),   // 1.3.6.1.4.1.42.2.17.1.1
                                     DerTlv(0x05, Bytes())}),
                             DerTlv(0x04, prot)});
        PutU32(body, 1);   // private key entry
        PutUtf(body, alias.empty() ? std::string("tomcat") : JksAlias(alias));
        PutU64(body, ms);
        PutBytes(body, epki.data(), epki.size());
        PutU32(body, (unsigned long)chain.size());
        for (auto& c : chain) {
            PutUtf(body, "X.509");
            PutBytes(body, c->pbCertEncoded, c->cbCertEncoded);
        }
    } else {
        // 沒有私鑰：做成只有信任憑證的 truststore
        PutU32(body, (unsigned long)chain.size());
        std::vector<std::string> used;
        for (auto& c : chain) {
            std::string a = JksAlias(CertDisplayName(c.get())), base = a;
            for (int n = 2; std::find(used.begin(), used.end(), a) != used.end(); n++) a = base + "-" + std::to_string(n);
            used.push_back(a);
            PutU32(body, 2);   // trusted certificate entry
            PutUtf(body, a);
            PutU64(body, ms);
            PutUtf(body, "X.509");
            PutBytes(body, c->pbCertEncoded, c->cbCertEncoded);
        }
    }
    // ---- 完整性雜湊 ----
    static const char kWhitener[] = "Mighty Aphrodite";
    Bytes in = pw, mac;
    in.insert(in.end(), kWhitener, kWhitener + sizeof(kWhitener) - 1);
    in.insert(in.end(), body.begin(), body.end());
    ok = ok && HashData(BCRYPT_SHA1_ALGORITHM, in, mac);
    SecureZeroMemory(in.data(), in.size());
    SecureZeroMemory(pw.data(), pw.size());
    if (!ok) { err = L"KeyStore 雜湊計算失敗"; return false; }
    body.insert(body.end(), mac.begin(), mac.end());
    out.swap(body);
    return true;
}

}  // namespace cc

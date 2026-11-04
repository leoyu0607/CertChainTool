// selftest.cpp - certcore 命令列測試
// 用法：selftest.exe <測試資料目錄> <輸出目錄>
#include "../src/certcore.h"

#include <bcrypt.h>
#include <cstdio>
#include <io.h>
#include <fcntl.h>

using namespace cc;

static int g_fail = 0, g_pass = 0;
static std::wstring g_dir, g_out;

#define CHECK(cond, msg)                                         \
    do {                                                         \
        if (cond) { g_pass++; wprintf(L"  [OK]   %ls\n", msg); } \
        else { g_fail++; wprintf(L"  [FAIL] %ls  (%hs:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

static PasswordPrompt Pwd(const wchar_t* pwd, int wrongFirst = 0) {
    auto counter = std::make_shared<int>(wrongFirst);
    return [pwd, counter](const std::wstring&, std::wstring& out) {
        if ((*counter)-- > 0) { out = L"wrong-password"; return true; }
        out = pwd;
        return true;
    };
}

static void PrintMessages(const LoadResult& r) {
    for (auto& m : r.messages) wprintf(L"         訊息：%ls\n", m.c_str());
}

static LoadResult Load(Workspace& ws, const wchar_t* name, const PasswordPrompt& p = nullptr) {
    LoadResult r = ws.LoadFile(g_dir + L"\\" + name, p);
    PrintMessages(r);
    return r;
}

static std::wstring RoleName(Role r) {
    switch (r) {
        case Role::Leaf: return L"終端";
        case Role::Intermediate: return L"中繼";
        case Role::Root: return L"根";
        default: return L"未使用";
    }
}

static std::wstring OrderString(const Workspace& ws) {
    std::wstring s;
    for (auto& e : ws.BuildOrder()) {
        if (!s.empty()) s += L" > ";
        s += RoleName(e.role) + L":" + CertDisplayName(ws.certs[e.certIndex].cert.get());
        if (ws.certs[e.certIndex].keyIndex >= 0) s += L"(key)";
    }
    return s;
}

static const wchar_t* kExpectedChain = L"終端:www.example.test(key) > 中繼:Test Intermediate CA > 根:Test Root CA";

static void ExpectFullChainWithKey(Workspace& ws, const wchar_t* what) {
    std::wstring o = OrderString(ws);
    wprintf(L"         順序：%ls\n", o.c_str());
    CHECK(o == kExpectedChain, what);
}

static std::vector<CertPtr> ChainCerts(const Workspace& ws, bool includeRoot) {
    std::vector<CertPtr> v;
    for (auto& e : ws.BuildOrder()) {
        if (e.role == Role::Unused) continue;
        if (e.role == Role::Root && !includeRoot) continue;
        v.push_back(ws.certs[e.certIndex].cert);
    }
    return v;
}

static const KeyItem* LeafKey(const Workspace& ws) {
    auto order = ws.BuildOrder();
    if (order.empty()) return nullptr;
    int k = ws.certs[order[0].certIndex].keyIndex;
    return k >= 0 ? &ws.keys[k] : nullptr;
}

int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_U8TEXT);
    if (argc < 3) {
        wprintf(L"用法：selftest <測試資料目錄> <輸出目錄>\n");
        return 2;
    }
    g_dir = argv[1];
    g_out = argv[2];
    CreateDirectoryW(g_out.c_str(), nullptr);

    wprintf(L"\n== 個別檔案亂序載入並排序 ==\n");
    {
        Workspace ws;
        Load(ws, L"root.crt");
        Load(ws, L"leaf.der");
        Load(ws, L"inter.crt");
        Load(ws, L"leaf.key");
        ExpectFullChainWithKey(ws, L"root/DER leaf/inter + PKCS#8 私鑰 → 正確排序且配對私鑰");
        auto r = Load(ws, L"leaf.crt");
        CHECK(r.certsDuplicated == 1 && ws.certs.size() == 3, L"重複憑證（PEM 與 DER 同一張）不重複加入");
    }

    wprintf(L"\n== PEM 合併檔 / P7B ==\n");
    for (const wchar_t* f : {L"bundle_shuffled.pem", L"chain.p7b", L"chain_pem.p7b"}) {
        Workspace ws;
        auto r = Load(ws, f);
        Load(ws, L"leaf_pkcs1.key");
        std::wstring msg = std::wstring(f) + L" → 3 張憑證、排序正確、PKCS#1 私鑰配對";
        CHECK(r.certsAdded == 3, (std::wstring(f) + L" 載入 3 張").c_str());
        ExpectFullChainWithKey(ws, msg.c_str());
    }

    wprintf(L"\n== 各種私鑰格式 ==\n");
    struct { const wchar_t* file; const wchar_t* pwd; int wrong; } keyCases[] = {
        {L"leaf_pkcs1.key", nullptr, 0},
        {L"leaf_key.der", nullptr, 0},
        {L"leaf_pbes2.key", L"test123", 1},
        {L"leaf_pbes2_sha1.key", L"test123", 0},
        {L"leaf_legacy_enc.key", L"test123", 1},
    };
    for (auto& kc : keyCases) {
        Workspace ws;
        Load(ws, L"bundle_shuffled.pem");
        auto r = Load(ws, kc.file, kc.pwd ? Pwd(kc.pwd, kc.wrong) : nullptr);
        std::wstring msg = std::wstring(kc.file) + (kc.wrong ? L"（先輸入錯誤密碼再重試）" : L"") + L" → 私鑰配對到終端憑證";
        CHECK(r.keysAdded == 1, (std::wstring(kc.file) + L" 讀到 1 把私鑰").c_str());
        ExpectFullChainWithKey(ws, msg.c_str());
    }
    {
        Workspace ws;
        Load(ws, L"bundle_shuffled.pem");
        std::wstring dummy;
        auto r = ws.LoadFile(g_dir + L"\\leaf_pbes2.key", [](const std::wstring&, std::wstring&) { return false; });
        CHECK(r.keysAdded == 0 && !r.messages.empty(), L"取消輸入密碼 → 不載入且有訊息");
    }
    for (const wchar_t* f : {L"ec.key", L"ec_pkcs8.key"}) {
        Workspace ws;
        Load(ws, L"ec.crt");
        Load(ws, L"inter.crt");
        Load(ws, L"root.crt");
        auto r = Load(ws, f);
        std::wstring o = OrderString(ws);
        wprintf(L"         順序：%ls  私鑰：%ls\n", o.c_str(), ws.keys.empty() ? L"-" : ws.keys[0].algName.c_str());
        CHECK(r.keysAdded == 1 && o.find(L"終端:ec.example.test(key)") == 0, (std::wstring(f) + L" EC 私鑰配對").c_str());
    }

    wprintf(L"\n== PFX 讀取 ==\n");
    for (auto f : {L"leaf_aes.pfx", L"leaf_3des.pfx"}) {
        Workspace ws;
        auto r = Load(ws, f, Pwd(L"test123", 1));
        CHECK(r.certsAdded == 3 && r.keysAdded == 1, (std::wstring(f) + L" → 3 張憑證 + 1 把私鑰").c_str());
        ExpectFullChainWithKey(ws, (std::wstring(f) + L" 排序與私鑰").c_str());
    }
    {
        Workspace ws;
        bool asked = false;
        auto r = ws.LoadFile(g_dir + L"\\ec_nopass.pfx", [&](const std::wstring&, std::wstring&) { asked = true; return false; });
        PrintMessages(r);
        CHECK(!asked && r.certsAdded == 1 && r.keysAdded == 1, L"無密碼 PFX 不詢問密碼即可讀取（EC）");
    }

    wprintf(L"\n== 匯出 ==\n");
    {
        Workspace ws;
        Load(ws, L"bundle_shuffled.pem");
        Load(ws, L"leaf.key");
        std::string pem;
        for (auto& c : ChainCerts(ws, false)) pem += CertToPem(c.get());
        WriteAll(g_out + L"\\fullchain.pem", pem.data(), pem.size());
        std::string pemRoot;
        for (auto& c : ChainCerts(ws, true)) pemRoot += CertToPem(c.get());
        WriteAll(g_out + L"\\fullchain_root.pem", pemRoot.data(), pemRoot.size());
        CHECK(ChainCerts(ws, false).size() == 2 && ChainCerts(ws, true).size() == 3, L"完整鏈（不含根 2 張 / 含根 3 張）");

        std::string k = KeyToPem(LeafKey(ws)->pkcs8);
        WriteAll(g_out + L"\\key_pkcs8.pem", k.data(), k.size());
        std::string k1;
        std::wstring err;
        CHECK(KeyToPkcs1Pem(LeafKey(ws)->pkcs8, k1, err), L"私鑰轉 PKCS#1");
        WriteAll(g_out + L"\\key_pkcs1.pem", k1.data(), k1.size());

        Bytes p7;
        CHECK(ExportP7b(ChainCerts(ws, true), p7, err), L"匯出 P7B");
        WriteAll(g_out + L"\\chain.p7b", p7.data(), p7.size());

        for (bool aes : {true, false}) {
            Bytes pfx;
            bool ok = ExportPfx(ChainCerts(ws, true), LeafKey(ws), L"Pa55word", aes, pfx, err);
            if (!ok) wprintf(L"         錯誤：%ls\n", err.c_str());
            std::wstring name = aes ? L"out_aes.pfx" : L"out_3des.pfx";
            CHECK(ok, (L"匯出 " + name).c_str());
            WriteAll(g_out + L"\\" + name, pfx.data(), pfx.size());
            Workspace ws2;
            auto r = ws2.LoadBytes(pfx, name, Pwd(L"Pa55word"));
            PrintMessages(r);
            ExpectFullChainWithKey(ws2, (name + L" 重新讀回：3 張憑證 + 私鑰").c_str());
        }
        {
            Workspace ws3;
            Load(ws3, L"ec.crt");
            Load(ws3, L"inter.crt");
            Load(ws3, L"ec.key");
            Bytes pfx;
            bool ok = ExportPfx(ChainCerts(ws3, true), LeafKey(ws3), L"", true, pfx, err);
            if (!ok) wprintf(L"         錯誤：%ls\n", err.c_str());
            WriteAll(g_out + L"\\out_ec.pfx", pfx.data(), pfx.size());
            Workspace ws4;
            bool asked = false;
            auto r = ws4.LoadBytes(pfx, L"out_ec.pfx", [&](const std::wstring&, std::wstring&) { asked = true; return false; });
            CHECK(ok && !asked && r.keysAdded == 1 && r.certsAdded == 2, L"EC 私鑰 + 空密碼 PFX 匯出並讀回");
        }
    }

    wprintf(L"\n== 憑證資訊與系統驗證 ==\n");
    {
        Workspace ws;
        Load(ws, L"bundle_shuffled.pem");
        auto order = ws.BuildOrder();
        std::wstring d = DescribeCert(ws.certs[order[0].certIndex].cert.get());
        CHECK(d.find(L"www.example.test") != std::wstring::npos && d.find(L"SHA-256") != std::wstring::npos, L"DescribeCert 內容");
        wprintf(L"%ls\n", d.c_str());
        std::vector<CertPtr> all;
        for (auto& c : ws.certs) all.push_back(c.cert);
        ChainReport rep = BuildSystemChain(ws.certs[order[0].certIndex].cert, all, false);
        bool warnOnly = false;
        wprintf(L"         系統驗證：元素 %zu 個，狀態：%ls\n", rep.elements.size(), TrustErrorText(rep.errorStatus, &warnOnly).c_str());
        CHECK(rep.ok && rep.elements.size() == 3 && (rep.errorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT), L"系統建鏈 3 層，根憑證不受信任（測試根 CA）");
    }

    wprintf(L"\n== CSR 與私鑰產生 ==\n");
    {
        struct { KeyType t; const wchar_t* name; } types[] = {
            {KeyType::Rsa2048, L"rsa2048"}, {KeyType::Rsa3072, L"rsa3072"}, {KeyType::EcP256, L"ecp256"}, {KeyType::EcP384, L"ecp384"}};
        for (auto& t : types) {
            CsrRequest req;
            req.cn = L"www.example.test";
            req.o = L"測試公司";
            req.ou = L"IT";
            req.l = L"台北市";
            req.st = L"Taiwan";
            req.c = L"tw";
            req.email = L"admin@example.test";
            req.sans = {L"www.example.test", L"DNS:Example.test", L"*.example.test", L"IP:10.0.0.1", L"2001:db8::1", L"www.example.test"};
            req.keyType = t.t;
            Bytes csr, key;
            std::wstring err;
            bool ok = GenerateCsr(req, csr, key, err);
            if (!ok) wprintf(L"         錯誤：%ls\n", err.c_str());
            CHECK(ok && !csr.empty() && !key.empty(), (std::wstring(L"產生 CSR + 新私鑰：") + t.name).c_str());
            std::string pem = CsrToPem(csr), kp = KeyToPem(key);
            WriteAll(g_out + L"\\csr_" + t.name + L".csr", pem.data(), pem.size());
            WriteAll(g_out + L"\\csr_" + t.name + L".key", kp.data(), kp.size());
        }
        // 沿用既有私鑰（續約）：RSA 與從 SEC1 載入的 EC 私鑰
        for (const wchar_t* f : {L"leaf.key", L"ec.key"}) {
            Workspace ws;
            Load(ws, f);
            CsrRequest req;
            req.cn = L"renew.example.test";
            req.existingKey = &ws.keys[0].pkcs8;
            Bytes csr, key;
            std::wstring err;
            bool ok = GenerateCsr(req, csr, key, err);
            if (!ok) wprintf(L"         錯誤：%ls\n", err.c_str());
            CHECK(ok && key == ws.keys[0].pkcs8, (std::wstring(L"沿用既有私鑰產生 CSR：") + f).c_str());
            std::string pem = CsrToPem(csr);
            WriteAll(g_out + L"\\csr_reuse_" + std::wstring(f) + L".csr", pem.data(), pem.size());
        }
        {
            CsrRequest req;
            Bytes csr, key;
            std::wstring err;
            CHECK(!GenerateCsr(req, csr, key, err), L"CN 空白 → 拒絕");
            req.cn = L"x";
            req.c = L"TWN";
            CHECK(!GenerateCsr(req, csr, key, err), L"國家代碼 3 碼 → 拒絕");
            req.c = L"";
            req.sans = {L"中文.tw"};
            CHECK(!GenerateCsr(req, csr, key, err), L"SAN 含非 ASCII → 拒絕");
        }
        // 加密私鑰匯出並以本工具讀回
        {
            Workspace ws;
            Load(ws, L"leaf.key");
            std::string enc;
            std::wstring err;
            CHECK(KeyToEncryptedPem(ws.keys[0].pkcs8, L"Secr3t!", enc, err), L"私鑰加密匯出（PBES2 AES-256）");
            WriteAll(g_out + L"\\key_encrypted.pem", enc.data(), enc.size());
            Workspace ws2;
            auto r = ws2.LoadBytes(Bytes(enc.begin(), enc.end()), L"key_encrypted.pem", Pwd(L"Secr3t!", 1));
            CHECK(r.keysAdded == 1 && ws2.keys[0].publicKeyBits == ws.keys[0].publicKeyBits, L"加密私鑰讀回且內容一致");
        }
    }

    wprintf(L"\n結果：%d 通過，%d 失敗\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}

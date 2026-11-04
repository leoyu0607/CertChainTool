// main.cpp - 憑證鏈工具（Win32 原生 UI）
#include "certcore.h"
#include "resource.h"

#include <commctrl.h>
#include <commdlg.h>
#include <cryptuiapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <uxtheme.h>

#include <algorithm>
#include <thread>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "cryptui.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "ole32.lib")

using namespace cc;

static const UINT WM_APP_VALIDATED = WM_APP + 1;
static const UINT WM_APP_LOADARGS = WM_APP + 2;
static const wchar_t* kTitle = L"憑證鏈工具";

// ---------------------------------------------------------------------------
// 全域狀態
// ---------------------------------------------------------------------------
static HINSTANCE g_inst;
static HWND g_hwnd, g_list, g_detail, g_status, g_chkRoot;
static HWND g_buttons[7];
static HFONT g_font;
static UINT g_dpi = 96;
static Workspace g_ws;
static std::vector<OrderEntry> g_order;
static std::vector<int> g_unmatched;
static std::wstring g_report;     // 最近一次驗證結果
static bool g_busy = false;
static bool g_filling = false;

static int S(int v) { return MulDiv(v, (int)g_dpi, 96); }

// 清單列的 lParam：>= 0 為憑證索引，< 0 為 -(私鑰索引 + 1)
static LPARAM CertParam(int i) { return i; }
static LPARAM KeyParam(int k) { return -(k + 1); }

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------
static void SetStatus(const std::wstring& s) { SendMessageW(g_status, SB_SETTEXTW, 0, (LPARAM)s.c_str()); }

static int Ask(const std::wstring& text, UINT flags = MB_YESNO | MB_ICONQUESTION) {
    return MessageBoxW(g_hwnd, text.c_str(), kTitle, flags);
}
static void Info(const std::wstring& text) { MessageBoxW(g_hwnd, text.c_str(), kTitle, MB_OK | MB_ICONINFORMATION); }
static void Error(const std::wstring& text) { MessageBoxW(g_hwnd, text.c_str(), kTitle, MB_OK | MB_ICONERROR); }

static std::wstring RoleText(Role r) {
    switch (r) {
        case Role::Leaf: return L"終端憑證";
        case Role::Intermediate: return L"中繼 CA";
        case Role::Root: return L"根 CA";
        default: return L"不在鏈上";
    }
}

static std::wstring SafeFileName(std::wstring s) {
    if (s.rfind(L"*.", 0) == 0) s = L"wildcard" + s.substr(1);
    for (auto& ch : s)
        if (wcschr(L"<>:\"/\\|?*", ch) || ch < 32) ch = L'_';
    while (!s.empty() && (s.back() == L'.' || s.back() == L' ')) s.pop_back();
    return s.empty() ? L"certificate" : s;
}

static std::wstring ToCrlf(const std::string& lf) {
    std::wstring w = FromUtf8(lf), out;
    for (wchar_t ch : w) {
        if (ch == L'\n') out += L"\r\n";
        else out += ch;
    }
    return out;
}

static bool CopyToClipboard(const std::wstring& text) {
    if (!OpenClipboard(g_hwnd)) return false;
    EmptyClipboard();
    size_t cb = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, cb);
    bool ok = false;
    if (h) {
        memcpy(GlobalLock(h), text.c_str(), cb);
        GlobalUnlock(h);
        ok = SetClipboardData(CF_UNICODETEXT, h) != nullptr;
        if (!ok) GlobalFree(h);
    }
    CloseClipboard();
    return ok;
}

static bool SaveDialog(const wchar_t* title, const wchar_t* filter, const wchar_t* defExt, const std::wstring& name, std::wstring& out) {
    wchar_t buf[MAX_PATH * 4];
    wcsncpy_s(buf, name.c_str(), _TRUNCATE);
    OPENFILENAMEW ofn = {sizeof(ofn)};
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrTitle = title;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = _countof(buf);
    ofn.lpstrDefExt = defExt;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER;
    if (!GetSaveFileNameW(&ofn)) return false;
    out = buf;
    return true;
}

// ---------------------------------------------------------------------------
// 密碼對話框
// ---------------------------------------------------------------------------
struct PwdData {
    std::wstring prompt;
    std::wstring password;
    bool aes = true;
    std::wstring caption;     // 空白時使用對話框預設標題
    bool showAes = true;      // IDD_PASSWORD_NEW：是否顯示 AES 選項
    bool allowEmpty = true;   // IDD_PASSWORD_NEW：是否允許空白密碼
};

static INT_PTR CALLBACK PwdProc(HWND d, UINT m, WPARAM w, LPARAM l) {
    auto* data = (PwdData*)GetWindowLongPtrW(d, DWLP_USER);
    switch (m) {
        case WM_INITDIALOG:
            SetWindowLongPtrW(d, DWLP_USER, l);
            data = (PwdData*)l;
            SetDlgItemTextW(d, IDC_PROMPT, data->prompt.c_str());
            CheckDlgButton(d, IDC_AES, data->aes ? BST_CHECKED : BST_UNCHECKED);
            if (!data->caption.empty()) SetWindowTextW(d, data->caption.c_str());
            if (!data->showAes) {
                for (int id : {IDC_AES, IDC_AESNOTE})
                    if (HWND h = GetDlgItem(d, id)) ShowWindow(h, SW_HIDE);
            }
            SetFocus(GetDlgItem(d, IDC_PWD1));
            return FALSE;
        case WM_COMMAND:
            switch (LOWORD(w)) {
                case IDC_SHOWPWD: {
                    bool show = IsDlgButtonChecked(d, IDC_SHOWPWD) == BST_CHECKED;
                    for (int id : {IDC_PWD1, IDC_PWD2}) {
                        HWND e = GetDlgItem(d, id);
                        if (!e) continue;
                        SendMessageW(e, EM_SETPASSWORDCHAR, show ? 0 : 0x25CF, 0);
                        InvalidateRect(e, nullptr, TRUE);
                    }
                    return TRUE;
                }
                case IDOK: {
                    wchar_t p1[512] = {}, p2[512] = {};
                    GetDlgItemTextW(d, IDC_PWD1, p1, 512);
                    bool confirm = GetDlgItem(d, IDC_PWD2) != nullptr;
                    if (confirm) {
                        GetDlgItemTextW(d, IDC_PWD2, p2, 512);
                        if (wcscmp(p1, p2) != 0) {
                            MessageBoxW(d, L"兩次輸入的密碼不一致。", kTitle, MB_OK | MB_ICONWARNING);
                            return TRUE;
                        }
                        if (!*p1 && !data->allowEmpty) {
                            MessageBoxW(d, L"請輸入密碼。", kTitle, MB_OK | MB_ICONWARNING);
                            return TRUE;
                        }
                        if (!*p1 && MessageBoxW(d, L"沒有設定密碼，PFX 內的私鑰等於沒有保護。\n確定不設密碼嗎？", kTitle, MB_YESNO | MB_ICONWARNING) != IDYES)
                            return TRUE;
                        data->aes = IsDlgButtonChecked(d, IDC_AES) == BST_CHECKED;
                    }
                    data->password = p1;
                    SecureZeroMemory(p1, sizeof(p1));
                    SecureZeroMemory(p2, sizeof(p2));
                    EndDialog(d, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                    EndDialog(d, IDCANCEL);
                    return TRUE;
            }
            break;
    }
    return FALSE;
}

static PasswordPrompt GuiPrompt() {
    return [](const std::wstring& prompt, std::wstring& pwd) {
        PwdData data;
        data.prompt = prompt;
        if (DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_PASSWORD), g_hwnd, PwdProc, (LPARAM)&data) != IDOK) return false;
        pwd = data.password;
        SecureZeroMemory(data.password.data(), data.password.size() * sizeof(wchar_t));
        return true;
    };
}

// ---------------------------------------------------------------------------
// 清單與明細
// ---------------------------------------------------------------------------
static LPARAM SelectedParam(bool* has = nullptr) {
    int i = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    if (has) *has = i >= 0;
    if (i < 0) return 0;
    LVITEMW it = {LVIF_PARAM, i};
    ListView_GetItem(g_list, &it);
    return it.lParam;
}

static int SelectedCert() {
    bool has;
    LPARAM p = SelectedParam(&has);
    return has && p >= 0 ? (int)p : -1;
}

static int SelectedKey() {
    bool has;
    LPARAM p = SelectedParam(&has);
    if (!has) return -1;
    if (p < 0) return (int)(-p - 1);
    return g_ws.certs[p].keyIndex;
}

static const OrderEntry* EntryOf(int certIndex) {
    for (auto& e : g_order)
        if (e.certIndex == certIndex) return &e;
    return nullptr;
}

static std::wstring StatusText(const OrderEntry& e) {
    PCCERT_CONTEXT c = g_ws.certs[e.certIndex].cert.get();
    std::wstring s;
    int days = DaysRemaining(c);
    if (NotYetValid(c)) s = L"尚未生效";
    else if (days < 0) s = L"已過期";
    else if (days <= 30) s = L"即將到期（剩 " + std::to_wstring(days) + L" 天）";
    else s = L"有效（剩 " + std::to_wstring(days) + L" 天）";
    if (e.issuerMissing) s += L"・缺少上層憑證";
    return s;
}

static std::wstring ChainSummary() {
    std::wstring s;
    if (g_ws.certs.empty() && g_ws.keys.empty()) {
        return L"請把憑證或私鑰檔案拖曳到這個視窗，或按「開啟檔案」。\r\n\r\n"
               L"支援格式：\r\n"
               L"  ・憑證：PEM（.pem/.crt/.cer，可一個檔案多張）、DER（.cer/.der）、PKCS#7（.p7b/.p7c）\r\n"
               L"  ・容器：PKCS#12（.pfx/.p12，含私鑰）\r\n"
               L"  ・私鑰：PKCS#8、RSA PKCS#1、EC（SEC1），明文或加密皆可\r\n"
               L"  ・已數位簽章的 .exe / .dll（取出簽章憑證）\r\n"
               L"  ・也可以直接從剪貼簿貼上 PEM 文字（Ctrl+V）\r\n\r\n"
               L"載入後會自動依「終端 → 中繼 → 根」排序。缺少的中繼憑證可以按「補齊並驗證」，\r\n"
               L"由 Windows 從本機憑證存放區或網路（AIA）補上，並檢查信任與撤銷狀態。\r\n\r\n"
               L"要申請新憑證：按「產生 CSR / 自簽...」(Ctrl+N)，會同時產生私鑰。把 CSR 送給 CA，\r\n"
               L"拿到簽發的憑證後拖進來，會自動配對私鑰並組成憑證鏈。\r\n"
               L"測試或內部用途也可以直接產生自簽憑證，再匯出成 PFX 或 Tomcat 用的 Java KeyStore。";
    }
    s += L"【憑證鏈】\r\n";
    int n = 0;
    bool missing = false;
    for (auto& e : g_order) {
        if (e.role == Role::Unused) continue;
        auto& it = g_ws.certs[e.certIndex];
        s += L"  " + std::to_wstring(++n) + L". [" + RoleText(e.role) + L"] " + CertDisplayName(it.cert.get());
        if (it.keyIndex >= 0) s += L"　（有私鑰）";
        s += L"\r\n";
        if (e.issuerMissing) {
            missing = true;
            s += L"     ↑ 找不到簽發者：" + CertIssuerDisplayName(it.cert.get()) + L"\r\n";
        }
    }
    if (missing)
        s += L"\r\n△ 憑證鏈不完整。請載入上層 CA 憑證，或按「補齊並驗證」(F5) 由 Windows 自動取得。\r\n";
    int unused = 0;
    for (auto& e : g_order)
        if (e.role == Role::Unused) unused++;
    if (unused)
        s += L"\r\n有 " + std::to_wstring(unused) + L" 張憑證不在這條鏈上。若要改用別張當終端憑證，請在清單上按右鍵「設為終端憑證」。\r\n";
    if (!g_unmatched.empty()) {
        s += L"\r\n有 " + std::to_wstring(g_unmatched.size()) + L" 把私鑰找不到對應的憑證：\r\n";
        for (int k : g_unmatched) s += L"  ・" + g_ws.keys[k].algName + L"（" + g_ws.keys[k].source + L"）\r\n";
    }
    auto& leaf = g_ws.certs[g_order.front().certIndex];
    if (leaf.keyIndex < 0) s += L"\r\n終端憑證沒有對應的私鑰；若要匯出 PFX，請一併載入私鑰檔。\r\n";
    if (!g_report.empty()) s += L"\r\n" + g_report;
    return s;
}

static void UpdateDetail() {
    std::wstring s;
    bool has;
    LPARAM p = SelectedParam(&has);
    if (!has) {
        s = ChainSummary();
    } else if (p < 0) {
        const KeyItem& k = g_ws.keys[-p - 1];
        s = L"【私鑰】" + k.algName + L"\r\n來源：" + k.source +
            L"\r\n\r\n找不到與這把私鑰對應的憑證。請載入它的憑證，或確認私鑰與憑證是否為同一組。";
    } else {
        const CertItem& it = g_ws.certs[p];
        const OrderEntry* e = EntryOf((int)p);
        s = L"【" + (e ? RoleText(e->role) : L"") + L"】" + CertDisplayName(it.cert.get()) + L"\r\n";
        s += L"來源：" + it.source + L"\r\n";
        if (it.keyIndex >= 0) s += L"私鑰：有（" + g_ws.keys[it.keyIndex].algName + L"，來源 " + g_ws.keys[it.keyIndex].source + L"）\r\n";
        else s += L"私鑰：無\r\n";
        if (e && e->issuerMissing) s += L"△ 清單中找不到它的簽發者：" + CertIssuerDisplayName(it.cert.get()) + L"\r\n";
        s += L"\r\n" + DescribeCert(it.cert.get());
    }
    SetWindowTextW(g_detail, s.c_str());
}

static void UpdateStatusBar() {
    int chain = 0;
    for (auto& e : g_order)
        if (e.role != Role::Unused) chain++;
    std::wstring s;
    if (g_ws.certs.empty()) s = L"尚未載入憑證";
    else s = L"共 " + std::to_wstring(g_ws.certs.size()) + L" 張憑證、" + std::to_wstring(g_ws.keys.size()) + L" 把私鑰　｜　憑證鏈 " + std::to_wstring(chain) + L" 層";
    SetStatus(s);
}

static void EnableControls() {
    bool any = !g_ws.certs.empty();
    EnableWindow(g_buttons[2], any && !g_busy);
    EnableWindow(g_buttons[3], any);
    EnableWindow(g_buttons[4], any || !g_ws.keys.empty());
    EnableWindow(g_buttons[5], any || !g_ws.keys.empty());
}

static void InsertRow(int row, LPARAM param, const std::vector<std::wstring>& cols) {
    LVITEMW it = {};
    it.mask = LVIF_TEXT | LVIF_PARAM;
    it.iItem = row;
    it.lParam = param;
    it.pszText = (LPWSTR)cols[0].c_str();
    int idx = ListView_InsertItem(g_list, &it);
    for (int c = 1; c < (int)cols.size(); c++) ListView_SetItemText(g_list, idx, c, (LPWSTR)cols[c].c_str());
}

// 重新排序並重繪清單。keepSel：嘗試保留目前選取
static void Refresh(bool keepSel = true) {
    bool had;
    LPARAM sel = SelectedParam(&had);
    g_order = g_ws.BuildOrder();
    g_unmatched = g_ws.UnmatchedKeys();

    g_filling = true;
    SendMessageW(g_list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_list);
    int row = 0, n = 0;
    for (auto& e : g_order) {
        auto& it = g_ws.certs[e.certIndex];
        PCCERT_CONTEXT c = it.cert.get();
        InsertRow(row++, CertParam(e.certIndex),
                  {e.role == Role::Unused ? L"-" : std::to_wstring(++n), RoleText(e.role), CertDisplayName(c), CertIssuerDisplayName(c),
                   FormatFileTime(c->pCertInfo->NotAfter, false), StatusText(e), it.keyIndex >= 0 ? L"有" : L"", it.source});
    }
    for (int k : g_unmatched)
        InsertRow(row++, KeyParam(k), {L"-", L"私鑰（未配對）", g_ws.keys[k].algName, L"", L"", L"找不到對應的憑證", L"有", g_ws.keys[k].source});
    if (keepSel && had) {
        for (int i = 0; i < row; i++) {
            LVITEMW it = {LVIF_PARAM, i};
            ListView_GetItem(g_list, &it);
            if (it.lParam == sel) {
                ListView_SetItemState(g_list, i, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                ListView_EnsureVisible(g_list, i, FALSE);
                break;
            }
        }
    }
    SendMessageW(g_list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_list, nullptr, TRUE);
    g_filling = false;
    UpdateDetail();
    UpdateStatusBar();
    EnableControls();
}

// ---------------------------------------------------------------------------
// 載入
// ---------------------------------------------------------------------------
static void ReportLoad(const LoadResult& total, int files) {
    std::wstring s = L"已載入 " + std::to_wstring(files) + L" 個來源：新增 " + std::to_wstring(total.certsAdded) + L" 張憑證、" +
                     std::to_wstring(total.keysAdded) + L" 把私鑰";
    if (total.certsDuplicated) s += L"（" + std::to_wstring(total.certsDuplicated) + L" 張重複已略過）";
    SetStatus(s);
    if (!total.messages.empty()) {
        std::wstring m;
        for (auto& x : total.messages) m += L"・" + x + L"\n";
        MessageBoxW(g_hwnd, m.c_str(), kTitle, MB_OK | MB_ICONWARNING);
    }
}

static void Merge(LoadResult& total, const LoadResult& r) {
    total.certsAdded += r.certsAdded;
    total.certsDuplicated += r.certsDuplicated;
    total.keysAdded += r.keysAdded;
    total.messages.insert(total.messages.end(), r.messages.begin(), r.messages.end());
}

static void CollectFiles(const std::wstring& path, std::vector<std::wstring>& out) {
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((path + L"\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring name = fd.cFileName;
            size_t dot = name.find_last_of(L'.');
            std::wstring ext = dot == std::wstring::npos ? L"" : name.substr(dot + 1);
            for (auto& ch : ext) ch = (wchar_t)towlower(ch);
            static const wchar_t* exts[] = {L"pem", L"crt", L"cer", L"der", L"p7b", L"p7c", L"pfx", L"p12", L"key", L"txt", L"ca-bundle"};
            for (auto e : exts)
                if (ext == e) { out.push_back(path + L"\\" + name); break; }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    } else {
        out.push_back(path);
    }
}

static void LoadPaths(const std::vector<std::wstring>& paths) {
    std::vector<std::wstring> files;
    for (auto& p : paths) CollectFiles(p, files);
    if (files.empty()) {
        SetStatus(L"沒有可載入的檔案");
        return;
    }
    LoadResult total;
    HCURSOR old = SetCursor(LoadCursor(nullptr, IDC_WAIT));
    for (auto& f : files) Merge(total, g_ws.LoadFile(f, GuiPrompt()));
    SetCursor(old);
    g_report.clear();
    Refresh();
    ReportLoad(total, (int)files.size());
}

static void OnOpen() {
    std::vector<wchar_t> buf(64 * 1024);
    OPENFILENAMEW ofn = {sizeof(ofn)};
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrTitle = L"開啟憑證或私鑰檔案（可多選）";
    ofn.lpstrFilter = L"憑證與私鑰\0*.cer;*.crt;*.pem;*.der;*.p7b;*.p7c;*.pfx;*.p12;*.key;*.txt;*.ca-bundle\0"
                      L"所有檔案 (*.*)\0*.*\0";
    ofn.lpstrFile = buf.data();
    ofn.nMaxFile = (DWORD)buf.size();
    ofn.Flags = OFN_ALLOWMULTISELECT | OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) return;
    std::vector<std::wstring> parts;
    for (const wchar_t* p = buf.data(); *p; p += wcslen(p) + 1) parts.push_back(p);
    std::vector<std::wstring> paths;
    if (parts.size() == 1) paths = parts;
    else
        for (size_t i = 1; i < parts.size(); i++) paths.push_back(parts[0] + L"\\" + parts[i]);
    LoadPaths(paths);
}

static void OnOpenFolder() {
    BROWSEINFOW bi = {};
    bi.hwndOwner = g_hwnd;
    bi.lpszTitle = L"選擇資料夾（載入其中所有憑證與私鑰檔案）";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return;
    wchar_t path[MAX_PATH * 2];
    bool ok = SHGetPathFromIDListEx(pidl, path, _countof(path), GPFIDL_DEFAULT) != FALSE;
    CoTaskMemFree(pidl);
    if (ok) LoadPaths({path});
}

static void OnPaste() {
    if (!IsClipboardFormatAvailable(CF_UNICODETEXT) || !OpenClipboard(g_hwnd)) {
        SetStatus(L"剪貼簿沒有文字");
        return;
    }
    std::wstring text;
    if (HANDLE h = GetClipboardData(CF_UNICODETEXT)) {
        if (auto p = (const wchar_t*)GlobalLock(h)) {
            text = p;
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    std::string u = ToUtf8(text);
    if (u.find("-----BEGIN ") == std::string::npos) {
        Info(L"剪貼簿的內容不是 PEM 格式（找不到 -----BEGIN ...----- 區塊）。");
        return;
    }
    LoadResult r = g_ws.LoadBytes(Bytes(u.begin(), u.end()), L"剪貼簿", GuiPrompt());
    g_report.clear();
    Refresh();
    ReportLoad(r, 1);
}

// ---------------------------------------------------------------------------
// 編輯
// ---------------------------------------------------------------------------
static void OnRemove() {
    std::vector<int> certs, keys;
    for (int i = -1; (i = ListView_GetNextItem(g_list, i, LVNI_SELECTED)) >= 0;) {
        LVITEMW it = {LVIF_PARAM, i};
        ListView_GetItem(g_list, &it);
        if (it.lParam >= 0) certs.push_back((int)it.lParam);
        else keys.push_back((int)(-it.lParam - 1));
    }
    if (certs.empty() && keys.empty()) {
        SetStatus(L"請先在清單中選取要移除的項目");
        return;
    }
    std::sort(certs.rbegin(), certs.rend());
    std::sort(keys.rbegin(), keys.rend());
    for (int c : certs) g_ws.RemoveCert(c);
    for (int k : keys) g_ws.RemoveKey(k);
    g_report.clear();
    Refresh(false);
}

static void OnClear() {
    if (g_ws.certs.empty() && g_ws.keys.empty()) return;
    if (Ask(L"確定要清除所有憑證與私鑰嗎？") != IDYES) return;
    g_ws.Clear();
    g_report.clear();
    Refresh(false);
}

static void OnSetLeaf(bool automatic) {
    if (automatic) {
        g_ws.leafOverride = nullptr;
    } else {
        int c = SelectedCert();
        if (c < 0) {
            SetStatus(L"請先選取一張憑證");
            return;
        }
        g_ws.leafOverride = g_ws.certs[c].cert.get();
    }
    g_report.clear();
    Refresh();
}

static void OnView() {
    int c = SelectedCert();
    if (c < 0) {
        SetStatus(L"請先選取一張憑證");
        return;
    }
    // 把所有已載入的憑證放進額外存放區，讓「憑證路徑」頁能用到它們
    HCERTSTORE mem = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
    for (auto& it : g_ws.certs) CertAddCertificateContextToStore(mem, it.cert.get(), CERT_STORE_ADD_USE_EXISTING, nullptr);
    CRYPTUI_VIEWCERTIFICATE_STRUCTW v = {sizeof(v)};
    v.hwndParent = g_hwnd;
    v.pCertContext = g_ws.certs[c].cert.get();
    v.cStores = 1;
    v.rghStores = &mem;
    BOOL changed = FALSE;
    CryptUIDlgViewCertificateW(&v, &changed);
    CertCloseStore(mem, 0);
}

// ---------------------------------------------------------------------------
// 驗證
// ---------------------------------------------------------------------------
static void OnValidate() {
    if (g_busy || g_order.empty()) return;
    g_busy = true;
    EnableControls();
    SetStatus(L"正在由 Windows 建立並驗證憑證鏈（可能需要從網路下載中繼憑證與撤銷清單）...");
    CertPtr leaf = g_ws.certs[g_order.front().certIndex].cert;
    std::vector<CertPtr> all;
    for (auto& it : g_ws.certs) all.push_back(it.cert);
    HWND hwnd = g_hwnd;
    std::thread([leaf, all, hwnd] {
        auto* rep = new ChainReport(BuildSystemChain(leaf, all, true));
        if (!PostMessageW(hwnd, WM_APP_VALIDATED, 0, (LPARAM)rep)) delete rep;
    }).detach();
}

static void OnValidated(ChainReport* rep) {
    std::unique_ptr<ChainReport> guard(rep);
    g_busy = false;
    SYSTEMTIME now;
    GetLocalTime(&now);
    wchar_t ts[64];
    swprintf_s(ts, L"%04u-%02u-%02u %02u:%02u:%02u", now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond);
    std::wstring s = L"【Windows 驗證結果】" + std::wstring(ts) + L"\r\n";
    int added = 0;
    if (!rep->ok) {
        s += L"  ✕ 無法建立憑證鏈：" + rep->error + L"\r\n";
    } else {
        bool warnOnly = false;
        std::wstring err = TrustErrorText(rep->errorStatus, &warnOnly);
        if (rep->errorStatus == 0) s += L"  ○ 通過：憑證鏈完整，且根憑證受此電腦信任。\r\n";
        else if (warnOnly) s += L"  △ 憑證鏈完整且受信任，但：" + err + L"\r\n";
        else s += L"  ✕ 有問題：" + err + L"\r\n";
        s += L"\r\n  Windows 建出的憑證鏈：\r\n";
        for (size_t i = 0; i < rep->elements.size(); i++) {
            PCCERT_CONTEXT c = rep->elements[i].get();
            bool isNew = g_ws.AddCert(rep->elements[i], L"Windows 補齊（本機存放區 / AIA）");
            if (isNew) added++;
            std::wstring e = TrustErrorText(rep->elementErrors[i]);
            s += L"    " + std::to_wstring(i + 1) + L". " + CertDisplayName(c) + (isNew ? L"　〔新補上〕" : L"") + L"\r\n";
            if (!e.empty()) s += L"       → " + e + L"\r\n";
        }
        if (rep->errorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT)
            s += L"\r\n  註：若這是公司內部 CA，根憑證不受信任是正常的，只要內容正確即可；\r\n      要讓這台電腦信任它，可在 Windows 憑證對話框中按「安裝憑證」匯入到「受信任的根憑證授權單位」。\r\n";
        if (added) s += L"\r\n  已自動補上 " + std::to_wstring(added) + L" 張憑證。\r\n";
    }
    if (added) g_ws.MatchKeys();
    g_report = s;
    // 先清掉選取，讓明細顯示整體摘要與驗證結果
    ListView_SetItemState(g_list, -1, 0, LVIS_SELECTED);
    Refresh(false);
    SetStatus(added ? L"驗證完成，已補上 " + std::to_wstring(added) + L" 張憑證" : L"驗證完成");
}

// ---------------------------------------------------------------------------
// 匯出
// ---------------------------------------------------------------------------
static bool IncludeRoot() { return IsDlgButtonChecked(g_hwnd, IDC_CHK_ROOT) == BST_CHECKED; }

static std::vector<CertPtr> Chain(bool includeRoot) {
    std::vector<CertPtr> v;
    for (auto& e : g_order) {
        if (e.role == Role::Unused || (e.role == Role::Root && !includeRoot)) continue;
        v.push_back(g_ws.certs[e.certIndex].cert);
    }
    return v;
}

static const KeyItem* LeafKey() {
    if (g_order.empty()) return nullptr;
    int k = g_ws.certs[g_order.front().certIndex].keyIndex;
    return k >= 0 ? &g_ws.keys[k] : nullptr;
}

static std::wstring BaseName() {
    if (g_order.empty()) return L"certificate";
    return SafeFileName(CertDisplayName(g_ws.certs[g_order.front().certIndex].cert.get()));
}

// 鏈不完整時提醒
static bool ConfirmChain() {
    if (g_order.empty()) {
        Info(L"尚未載入憑證。");
        return false;
    }
    const OrderEntry* last = nullptr;
    for (auto& e : g_order)
        if (e.role != Role::Unused) last = &e;
    if (last && last->issuerMissing) {
        std::wstring msg = L"憑證鏈不完整：找不到「" + CertIssuerDisplayName(g_ws.certs[last->certIndex].cert.get()) +
                           L"」的憑證。\n\n建議先按「補齊並驗證」(F5)。仍要匯出目前的內容嗎？";
        return Ask(msg, MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
    }
    return true;
}

static void SaveText(const std::wstring& path, const std::string& text, const std::wstring& what) {
    if (WriteAll(path, text.data(), text.size())) SetStatus(L"已匯出" + what + L"：" + path);
    else Error(L"無法寫入檔案：" + path + L"\n" + LastErrorText(GetLastError()));
}

static void SaveBytes(const std::wstring& path, const Bytes& b, const std::wstring& what) {
    if (WriteAll(path, b.data(), b.size())) SetStatus(L"已匯出" + what + L"：" + path);
    else Error(L"無法寫入檔案：" + path + L"\n" + LastErrorText(GetLastError()));
}

static const wchar_t* kPemFilter = L"PEM 檔案 (*.pem;*.crt)\0*.pem;*.crt\0所有檔案 (*.*)\0*.*\0";
static const wchar_t* kKeyFilter = L"私鑰檔案 (*.key;*.pem)\0*.key;*.pem\0所有檔案 (*.*)\0*.*\0";

static void OnExport(int cmd) {
    std::wstring path, err;
    switch (cmd) {
        case ID_EXP_FULLCHAIN: {
            if (!ConfirmChain()) return;
            std::string pem;
            for (auto& c : Chain(IncludeRoot())) pem += CertToPem(c.get());
            if (SaveDialog(L"匯出完整憑證鏈", kPemFilter, L"pem", BaseName() + L"_fullchain.pem", path)) SaveText(path, pem, L"完整憑證鏈");
            break;
        }
        case ID_EXP_INTERMEDIATES: {
            if (!ConfirmChain()) return;
            auto chain = Chain(IncludeRoot());
            if (chain.size() < 2) {
                Info(L"憑證鏈中沒有中繼或根憑證可以匯出。");
                return;
            }
            std::string pem;
            for (size_t i = 1; i < chain.size(); i++) pem += CertToPem(chain[i].get());
            if (SaveDialog(L"匯出中繼憑證（CA bundle）", kPemFilter, L"pem", BaseName() + L"_ca-bundle.pem", path)) SaveText(path, pem, L"中繼憑證");
            break;
        }
        case ID_EXP_CHAIN_KEY: {
            const KeyItem* key = LeafKey();
            if (!key) {
                Info(L"終端憑證沒有對應的私鑰，請先載入私鑰。");
                return;
            }
            if (!ConfirmChain()) return;
            std::string pem;
            for (auto& c : Chain(IncludeRoot())) pem += CertToPem(c.get());
            pem += KeyToPem(key->pkcs8);
            if (SaveDialog(L"匯出憑證鏈 + 私鑰（未加密）", kPemFilter, L"pem", BaseName() + L"_chain_key.pem", path)) SaveText(path, pem, L"憑證鏈與私鑰");
            break;
        }
        case ID_EXP_P7B: {
            if (!ConfirmChain()) return;
            Bytes out;
            if (!ExportP7b(Chain(IncludeRoot()), out, err)) { Error(err); return; }
            if (SaveDialog(L"匯出 PKCS#7", L"PKCS#7 (*.p7b)\0*.p7b\0所有檔案 (*.*)\0*.*\0", L"p7b", BaseName() + L".p7b", path)) SaveBytes(path, out, L"P7B");
            break;
        }
        case ID_EXP_PFX: {
            if (g_order.empty()) { Info(L"尚未載入憑證。"); return; }
            const KeyItem* key = LeafKey();
            if (!key && Ask(L"終端憑證沒有對應的私鑰，匯出的 PFX 將只有憑證。\n仍要繼續嗎？", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return;
            if (!ConfirmChain()) return;
            PwdData data;
            data.prompt = L"PFX 會包含：" + std::to_wstring(Chain(IncludeRoot()).size()) + L" 張憑證" + (key ? L" + 私鑰" : L"");
            if (DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_PASSWORD_NEW), g_hwnd, PwdProc, (LPARAM)&data) != IDOK) return;
            Bytes out;
            bool ok = ExportPfx(Chain(IncludeRoot()), key, data.password, data.aes, out, err);
            SecureZeroMemory(data.password.data(), data.password.size() * sizeof(wchar_t));
            if (!ok) { Error(err); return; }
            if (SaveDialog(L"匯出 PFX", L"PKCS#12 (*.pfx;*.p12)\0*.pfx;*.p12\0所有檔案 (*.*)\0*.*\0", L"pfx", BaseName() + L".pfx", path)) SaveBytes(path, out, L"PFX");
            SecureZeroMemory(out.data(), out.size());
            break;
        }
        case ID_EXP_JKS: {
            if (g_order.empty()) { Info(L"尚未載入憑證。"); return; }
            const KeyItem* key = LeafKey();
            if (!key && Ask(L"終端憑證沒有對應的私鑰。\n\n要匯出成只含憑證的信任存放區（truststore）嗎？\n（給 Tomcat 當伺服器憑證用的話，需要先載入私鑰。）",
                            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return;
            if (!ConfirmChain()) return;
            auto chain = Chain(IncludeRoot());
            PwdData data;
            data.caption = L"設定 KeyStore 密碼";
            data.prompt = key ? L"包含 " + std::to_wstring(chain.size()) + L" 張憑證 + 私鑰，別名為 tomcat。私鑰密碼與 KeyStore 密碼相同（至少 6 個字元）。"
                              : L"包含 " + std::to_wstring(chain.size()) + L" 張信任憑證（至少 6 個字元）。";
            data.showAes = false;
            data.allowEmpty = false;
            for (;;) {
                if (DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_PASSWORD_NEW), g_hwnd, PwdProc, (LPARAM)&data) != IDOK) return;
                if (data.password.size() >= 6) break;
                Info(L"Java KeyStore 的密碼至少要 6 個字元。");
            }
            Bytes out;
            bool ok = ExportJks(chain, key, data.password, L"tomcat", out, err);
            SecureZeroMemory(data.password.data(), data.password.size() * sizeof(wchar_t));
            if (!ok) { Error(err); return; }
            if (SaveDialog(L"匯出 Java KeyStore", L"Java KeyStore (*.keystore;*.jks)\0*.keystore;*.jks\0所有檔案 (*.*)\0*.*\0", L"keystore",
                           key ? L"tomcat.keystore" : L"truststore.jks", path))
                SaveBytes(path, out, L"Java KeyStore");
            SecureZeroMemory(out.data(), out.size());
            break;
        }
        case ID_EXP_KEY_ENC: {
            const KeyItem* key = LeafKey();
            int sk = SelectedKey();
            if (sk >= 0) key = &g_ws.keys[sk];
            if (!key) { Info(L"沒有可匯出的私鑰。"); return; }
            PwdData data;
            data.caption = L"設定私鑰密碼";
            data.prompt = L"私鑰（" + key->algName + L"）將以 AES-256 加密";
            data.showAes = false;
            data.allowEmpty = false;
            if (DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_PASSWORD_NEW), g_hwnd, PwdProc, (LPARAM)&data) != IDOK) return;
            std::string pem;
            bool ok = KeyToEncryptedPem(key->pkcs8, data.password, pem, err);
            SecureZeroMemory(data.password.data(), data.password.size() * sizeof(wchar_t));
            if (!ok) { Error(err); return; }
            if (SaveDialog(L"匯出加密私鑰", kKeyFilter, L"key", BaseName() + L".key", path)) SaveText(path, pem, L"加密私鑰");
            break;
        }
        case ID_EXP_KEY_PKCS8:
        case ID_EXP_KEY_PKCS1:
        case ID_EXP_SEL_KEY: {
            int k = cmd == ID_EXP_SEL_KEY ? SelectedKey() : (LeafKey() ? (int)(LeafKey() - g_ws.keys.data()) : -1);
            if (k < 0) {
                Info(cmd == ID_EXP_SEL_KEY ? L"選取的項目沒有私鑰。" : L"終端憑證沒有對應的私鑰。");
                return;
            }
            std::string pem;
            if (cmd == ID_EXP_KEY_PKCS1) {
                if (!KeyToPkcs1Pem(g_ws.keys[k].pkcs8, pem, err)) { Error(err); return; }
            } else {
                pem = KeyToPem(g_ws.keys[k].pkcs8);
            }
            if (SaveDialog(L"匯出私鑰（未加密，請妥善保管）", kKeyFilter, L"key", BaseName() + L".key", path)) SaveText(path, pem, L"私鑰");
            SecureZeroMemory(pem.data(), pem.size());
            break;
        }
        case ID_EXP_COPY_FULLCHAIN: {
            if (!ConfirmChain()) return;
            std::string pem;
            for (auto& c : Chain(IncludeRoot())) pem += CertToPem(c.get());
            if (CopyToClipboard(ToCrlf(pem))) SetStatus(L"已複製完整憑證鏈 PEM 到剪貼簿");
            break;
        }
        case ID_EXP_SEL_PEM:
        case ID_EXP_SEL_DER:
        case ID_EXP_SEL_COPY: {
            int c = SelectedCert();
            if (c < 0) { SetStatus(L"請先選取一張憑證"); return; }
            PCCERT_CONTEXT ctx = g_ws.certs[c].cert.get();
            std::wstring name = SafeFileName(CertDisplayName(ctx));
            if (cmd == ID_EXP_SEL_COPY) {
                if (CopyToClipboard(ToCrlf(CertToPem(ctx)))) SetStatus(L"已複製憑證 PEM 到剪貼簿");
            } else if (cmd == ID_EXP_SEL_PEM) {
                if (SaveDialog(L"匯出憑證（PEM）", kPemFilter, L"crt", name + L".crt", path)) SaveText(path, CertToPem(ctx), L"憑證");
            } else {
                if (SaveDialog(L"匯出憑證（DER）", L"DER 憑證 (*.cer;*.der)\0*.cer;*.der\0所有檔案 (*.*)\0*.*\0", L"cer", name + L".cer", path))
                    SaveBytes(path, Bytes(ctx->pbCertEncoded, ctx->pbCertEncoded + ctx->cbCertEncoded), L"憑證");
            }
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// 產生 CSR
// ---------------------------------------------------------------------------
struct CsrDlgData {
    CsrRequest req;
    std::wstring sanText;
    bool cnToSan = true;
    int keyChoice = 0;          // 0..4 = 新金鑰種類，>= 5 為 g_ws.keys[keyChoice - 5]
    std::wstring password;
    bool selfSigned = false;    // true = 產生自簽憑證，false = 產生 CSR
    int days = 365;
};

static const wchar_t* kNewKeyText[] = {
    L"產生新的 RSA 2048 位元（建議，相容性最好）", L"產生新的 RSA 3072 位元", L"產生新的 RSA 4096 位元",
    L"產生新的 EC P-256（ECDSA）", L"產生新的 EC P-384（ECDSA）"};
static const KeyType kNewKeyType[] = {KeyType::Rsa2048, KeyType::Rsa3072, KeyType::Rsa4096, KeyType::EcP256, KeyType::EcP384};

static std::wstring NameAttr(PCCERT_CONTEXT c, LPCSTR oid) {
    wchar_t buf[512] = {};
    CertGetNameStringW(c, CERT_NAME_ATTR_TYPE, 0, (void*)oid, buf, 512);
    return buf;
}

// 從既有憑證帶入主體與 SAN（續約時方便）
static void PrefillFromCert(PCCERT_CONTEXT c, CsrDlgData& d) {
    d.req.cn = NameAttr(c, szOID_COMMON_NAME);
    d.req.o = NameAttr(c, szOID_ORGANIZATION_NAME);
    d.req.ou = NameAttr(c, szOID_ORGANIZATIONAL_UNIT_NAME);
    d.req.l = NameAttr(c, szOID_LOCALITY_NAME);
    d.req.st = NameAttr(c, szOID_STATE_OR_PROVINCE_NAME);
    d.req.c = NameAttr(c, szOID_COUNTRY_NAME);
    d.req.email = NameAttr(c, szOID_RSA_emailAddr);
    PCERT_EXTENSION ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2, c->pCertInfo->cExtension, c->pCertInfo->rgExtension);
    CERT_ALT_NAME_INFO* ani = nullptr;
    DWORD cb = 0;
    if (ext && CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, ext->Value.pbData, ext->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, &ani, &cb)) {
        for (DWORD i = 0; i < ani->cAltEntry; i++) {
            const CERT_ALT_NAME_ENTRY& e = ani->rgAltEntry[i];
            if (e.dwAltNameChoice == CERT_ALT_NAME_DNS_NAME) d.sanText += std::wstring(e.pwszDNSName) + L"\r\n";
            else if (e.dwAltNameChoice == CERT_ALT_NAME_IP_ADDRESS && e.IPAddress.cbData == 4) {
                const BYTE* a = e.IPAddress.pbData;
                d.sanText += std::to_wstring(a[0]) + L"." + std::to_wstring(a[1]) + L"." + std::to_wstring(a[2]) + L"." + std::to_wstring(a[3]) + L"\r\n";
            }
        }
        LocalFree(ani);
    }
}

static std::wstring GetText(HWND d, int id) {
    HWND h = GetDlgItem(d, id);
    std::wstring s(GetWindowTextLengthW(h), L'\0');
    GetWindowTextW(h, s.data(), (int)s.size() + 1);
    return s;
}

static INT_PTR CALLBACK CsrProc(HWND d, UINT m, WPARAM w, LPARAM l) {
    auto* data = (CsrDlgData*)GetWindowLongPtrW(d, DWLP_USER);
    switch (m) {
        case WM_INITDIALOG: {
            SetWindowLongPtrW(d, DWLP_USER, l);
            data = (CsrDlgData*)l;
            HWND combo = GetDlgItem(d, IDC_CSR_KEY);
            for (auto t : kNewKeyText) SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)t);
            for (auto& k : g_ws.keys) {
                std::wstring t = L"沿用已載入的私鑰：" + k.algName + L"（" + k.source + L"）";
                SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)t.c_str());
            }
            SendMessageW(combo, CB_SETCURSEL, data->keyChoice, 0);
            SetDlgItemTextW(d, IDC_CSR_CN, data->req.cn.c_str());
            SetDlgItemTextW(d, IDC_CSR_O, data->req.o.c_str());
            SetDlgItemTextW(d, IDC_CSR_OU, data->req.ou.c_str());
            SetDlgItemTextW(d, IDC_CSR_L, data->req.l.c_str());
            SetDlgItemTextW(d, IDC_CSR_ST, data->req.st.c_str());
            SetDlgItemTextW(d, IDC_CSR_C, data->req.c.c_str());
            SetDlgItemTextW(d, IDC_CSR_EMAIL, data->req.email.c_str());
            SetDlgItemTextW(d, IDC_CSR_SAN, data->sanText.c_str());
            SendDlgItemMessageW(d, IDC_CSR_C, EM_LIMITTEXT, 2, 0);
            CheckDlgButton(d, IDC_CSR_CNSAN, data->cnToSan ? BST_CHECKED : BST_UNCHECKED);
            CheckRadioButton(d, IDC_CSR_MODE_CSR, IDC_CSR_MODE_SELF, data->selfSigned ? IDC_CSR_MODE_SELF : IDC_CSR_MODE_CSR);
            SetDlgItemInt(d, IDC_CSR_DAYS, (UINT)data->days, FALSE);
            SendDlgItemMessageW(d, IDC_CSR_DAYS, EM_LIMITTEXT, 5, 0);
            EnableWindow(GetDlgItem(d, IDC_CSR_DAYS), data->selfSigned);
            SetFocus(GetDlgItem(d, IDC_CSR_CN));
            return FALSE;
        }
        case WM_COMMAND:
            if (LOWORD(w) == IDC_CSR_MODE_CSR || LOWORD(w) == IDC_CSR_MODE_SELF) {
                bool self = IsDlgButtonChecked(d, IDC_CSR_MODE_SELF) == BST_CHECKED;
                EnableWindow(GetDlgItem(d, IDC_CSR_DAYS), self);
                return TRUE;
            }
            if (LOWORD(w) == IDOK) {
                std::wstring p1 = GetText(d, IDC_CSR_PWD1), p2 = GetText(d, IDC_CSR_PWD2);
                if (p1 != p2) {
                    MessageBoxW(d, L"兩次輸入的私鑰密碼不一致。", kTitle, MB_OK | MB_ICONWARNING);
                    return TRUE;
                }
                bool self = IsDlgButtonChecked(d, IDC_CSR_MODE_SELF) == BST_CHECKED;
                BOOL daysOk = FALSE;
                UINT days = GetDlgItemInt(d, IDC_CSR_DAYS, &daysOk, FALSE);
                if (self && (!daysOk || days < 1 || days > 36500)) {
                    MessageBoxW(d, L"有效天數請輸入 1 到 36500 之間的數字。", kTitle, MB_OK | MB_ICONWARNING);
                    SetFocus(GetDlgItem(d, IDC_CSR_DAYS));
                    return TRUE;
                }
                data->selfSigned = self;
                if (self) data->days = (int)days;
                if (GetText(d, IDC_CSR_CN).find_first_not_of(L" \t") == std::wstring::npos) {
                    MessageBoxW(d, L"請輸入一般名稱（CN），通常是網站的網域名稱，例如 www.example.com。", kTitle, MB_OK | MB_ICONWARNING);
                    SetFocus(GetDlgItem(d, IDC_CSR_CN));
                    return TRUE;
                }
                data->keyChoice = (int)SendDlgItemMessageW(d, IDC_CSR_KEY, CB_GETCURSEL, 0, 0);
                data->req.cn = GetText(d, IDC_CSR_CN);
                data->req.o = GetText(d, IDC_CSR_O);
                data->req.ou = GetText(d, IDC_CSR_OU);
                data->req.l = GetText(d, IDC_CSR_L);
                data->req.st = GetText(d, IDC_CSR_ST);
                data->req.c = GetText(d, IDC_CSR_C);
                data->req.email = GetText(d, IDC_CSR_EMAIL);
                data->sanText = GetText(d, IDC_CSR_SAN);
                data->cnToSan = IsDlgButtonChecked(d, IDC_CSR_CNSAN) == BST_CHECKED;
                data->password = p1;
                SecureZeroMemory(p1.data(), p1.size() * sizeof(wchar_t));
                SecureZeroMemory(p2.data(), p2.size() * sizeof(wchar_t));
                EndDialog(d, IDOK);
                return TRUE;
            }
            if (LOWORD(w) == IDCANCEL) {
                EndDialog(d, IDCANCEL);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

static bool LooksLikeHostName(const std::wstring& s) {
    if (s.empty() || s.find(L'.') == std::wstring::npos) return false;
    for (wchar_t ch : s)
        if (!(ch < 128 && (iswalnum(ch) || ch == L'-' || ch == L'.' || ch == L'*'))) return false;
    return true;
}

static std::wstring FileNameOf(const std::wstring& path) { return path.substr(path.find_last_of(L'\\') + 1); }

// 把新私鑰存在 nearPath 旁邊（同名 .key），有密碼就加密；回傳實際路徑，沒存則回傳空字串
static std::wstring SaveNewKey(const std::wstring& nearPath, const std::wstring& base, const Bytes& key,
                               const std::wstring& password, const wchar_t* skipWarning, std::wstring& msg) {
    std::wstring keyPath = nearPath.substr(0, nearPath.find_last_of(L'.')) + L".key";
    if (GetFileAttributesW(keyPath.c_str()) != INVALID_FILE_ATTRIBUTES &&
        Ask(L"檔案已存在：\n" + keyPath + L"\n\n要覆寫嗎？選「否」可另選位置。", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
        while (!SaveDialog(L"儲存私鑰", kKeyFilter, L"key", base + L".key", keyPath)) {
            if (Ask(skipWarning, MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES) return {};
        }
    }
    std::string keyPem;
    std::wstring err;
    bool encrypted = !password.empty();
    if (encrypted) KeyToEncryptedPem(key, password, keyPem, err);
    else keyPem = KeyToPem(key);
    bool ok = WriteAll(keyPath, keyPem.data(), keyPem.size());
    SecureZeroMemory(keyPem.data(), keyPem.size());
    if (!ok) {
        Error(L"無法寫入私鑰檔案：" + keyPath);
        return {};
    }
    msg += L"\n私鑰（" + std::wstring(encrypted ? L"已加密" : L"未加密，請妥善保管") + L"）：\n" + keyPath + L"\n";
    return keyPath;
}

static void FinishSelfSigned(CsrDlgData& data, const Bytes& der, Bytes& key, const std::wstring& base) {
    bool reuse = data.req.existingKey != nullptr;
    CertPtr cert = CertFromDer(der.data(), der.size());
    std::wstring certPath, keyPath, msg = L"已產生自簽憑證（有效 " + std::to_wstring(data.days) + L" 天）";
    if (SaveDialog(L"儲存自簽憑證（可按取消，稍後再從「匯出」選單匯出）",
                   L"憑證 PEM (*.crt;*.pem)\0*.crt;*.pem\0所有檔案 (*.*)\0*.*\0", L"crt", base + L".crt", certPath)) {
        std::string pem = CertToPem(cert.get());
        if (WriteAll(certPath, pem.data(), pem.size())) {
            msg += L"：\n" + certPath + L"\n";
            if (!reuse) keyPath = SaveNewKey(certPath, base, key, data.password, L"不儲存私鑰的話，稍後仍可從「匯出」選單匯出。確定現在不儲存嗎？", msg);
        } else {
            Error(L"無法寫入檔案：" + certPath);
            certPath.clear();
        }
    } else {
        msg += L"，尚未存檔。\n";
    }
    std::wstring err;
    if (!reuse) g_ws.AddKey(key, L"新產生（" + (keyPath.empty() ? std::wstring(L"未存檔") : FileNameOf(keyPath)) + L"）", err);
    g_ws.AddCert(cert, L"自簽（" + (certPath.empty() ? std::wstring(L"未存檔") : FileNameOf(certPath)) + L"）");
    g_ws.MatchKeys();
    g_ws.leafOverride = cert.get();   // 清單裡有其他憑證時，仍以新憑證為終端憑證
    SecureZeroMemory(data.password.data(), data.password.size() * sizeof(wchar_t));
    SecureZeroMemory(key.data(), key.size());
    Refresh(false);
    msg += L"\n憑證和私鑰已載入到這個工具，可以直接從「匯出」選單匯出成 PFX、Java KeyStore（Tomcat）、fullchain PEM 等格式。"
           L"\n\n自簽憑證不受任何瀏覽器信任；要在用戶端電腦把它匯入「受信任的根憑證授權單位」，連線時才不會出現警告。";
    Info(msg);
    SetStatus(L"已產生自簽憑證：" + CertDisplayName(cert.get()));
}

// ---------------------------------------------------------------------------
// 關於
// ---------------------------------------------------------------------------
static const wchar_t* kVersion = L"1.1.0";
static const wchar_t* kRepoUrl = L"https://github.com/leoyu0607/CertChainTool";
static const wchar_t* kCoffeeUrl = L"https://buymeacoffee.com/leoyu0607";

static HRESULT CALLBACK AboutCallback(HWND h, UINT n, WPARAM, LPARAM l, LONG_PTR) {
    if (n == TDN_HYPERLINK_CLICKED) {
        auto url = (LPCWSTR)l;
        if (wcscmp(url, kRepoUrl) == 0 || wcscmp(url, kCoffeeUrl) == 0)   // 只開自己的連結
            ShellExecuteW(h, L"open", url, nullptr, nullptr, SW_SHOWNORMAL);
    }
    return S_OK;
}

static void OnAbout() {
    std::wstring title = std::wstring(kTitle) + L" " + kVersion;
    std::wstring footer = L"<a href=\"" + std::wstring(kRepoUrl) + L"\">GitHub：原始碼、更新與問題回報</a>\n"
                          L"覺得好用的話，歡迎 <a href=\"" + std::wstring(kCoffeeUrl) + L"\">☕ Buy Me a Coffee</a> 請我喝杯咖啡！";
    TASKDIALOGCONFIG tc = {sizeof(tc)};
    tc.hwndParent = g_hwnd;
    tc.hInstance = g_inst;
    tc.dwFlags = TDF_ENABLE_HYPERLINKS | TDF_USE_HICON_MAIN | TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
    tc.dwCommonButtons = TDCBF_OK_BUTTON;
    tc.pszWindowTitle = L"關於";
    tc.hMainIcon = (HICON)LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0);
    tc.pszMainInstruction = title.c_str();
    tc.pszContent = L"合併、排序、補齊與驗證憑證鏈；產生 CSR 與自簽憑證；"
                    L"在 PEM / DER / P7B / PFX / Java KeyStore 之間轉換。\n\n"
                    L"只使用 Windows 內建的 CryptoAPI / CNG，不需要 OpenSSL。"
                    L"私鑰只存在記憶體中，不會寫入 Windows 憑證存放區。";
    tc.pszFooter = footer.c_str();
    tc.pfCallback = AboutCallback;
    tc.cxWidth = 270;   // DLU
    TaskDialogIndirect(&tc, nullptr, nullptr, nullptr);
    if (tc.hMainIcon) DestroyIcon(tc.hMainIcon);
}

static void OnCsr() {
    CsrDlgData data;
    int sel = SelectedCert();
    if (sel >= 0) PrefillFromCert(g_ws.certs[sel].cert.get(), data);

    Bytes csr, key;
    for (;;) {
        if (DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_CSR), g_hwnd, CsrProc, (LPARAM)&data) != IDOK) return;
        // 整理 SAN
        data.req.sans.clear();
        std::wstring cn = data.req.cn;
        cn.erase(0, cn.find_first_not_of(L" \t"));
        cn.erase(cn.find_last_not_of(L" \t") + 1);
        if (data.cnToSan && LooksLikeHostName(cn)) data.req.sans.push_back(cn);
        size_t pos = 0;
        const std::wstring& t = data.sanText;
        while (pos <= t.size()) {
            size_t nl = t.find_first_of(L"\r\n,;", pos);
            std::wstring item = t.substr(pos, nl == std::wstring::npos ? std::wstring::npos : nl - pos);
            if (!item.empty()) data.req.sans.push_back(item);
            if (nl == std::wstring::npos) break;
            pos = nl + 1;
        }
        bool reuse = data.keyChoice >= (int)_countof(kNewKeyType);
        data.req.existingKey = reuse ? &g_ws.keys[data.keyChoice - _countof(kNewKeyType)].pkcs8 : nullptr;
        if (!reuse) data.req.keyType = kNewKeyType[data.keyChoice];

        std::wstring err;
        HCURSOR old = SetCursor(LoadCursor(nullptr, IDC_WAIT));
        bool ok = data.selfSigned ? GenerateSelfSigned(data.req, data.days, csr, key, err) : GenerateCsr(data.req, csr, key, err);
        SetCursor(old);
        if (ok) break;
        Error(err);   // 回到對話框修正
    }
    bool reuse = data.req.existingKey != nullptr;
    std::wstring base = SafeFileName(data.req.cn);

    if (data.selfSigned) {
        FinishSelfSigned(data, csr, key, base);
        return;
    }

    std::wstring csrPath;
    while (!SaveDialog(L"儲存 CSR", L"CSR (*.csr)\0*.csr\0PEM (*.pem)\0*.pem\0所有檔案 (*.*)\0*.*\0", L"csr", base + L".csr", csrPath)) {
        if (reuse || Ask(L"沒有儲存 CSR，新產生的私鑰也會一起丟棄。確定要放棄嗎？", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES) {
            SecureZeroMemory(key.data(), key.size());
            return;
        }
    }
    std::string csrPem = CsrToPem(csr);
    if (!WriteAll(csrPath, csrPem.data(), csrPem.size())) {
        Error(L"無法寫入檔案：" + csrPath);
        return;
    }

    std::wstring msg = L"已產生 CSR：\n" + csrPath + L"\n";
    if (!reuse) {
        std::wstring keyPath = SaveNewKey(csrPath, base, key, data.password, L"不儲存私鑰的話，CA 簽發的憑證將無法使用。確定不儲存嗎？", msg);
        std::wstring err;
        g_ws.AddKey(key, L"新產生（" + (keyPath.empty() ? std::wstring(L"未存檔") : FileNameOf(keyPath)) + L"）", err);
    }
    SecureZeroMemory(data.password.data(), data.password.size() * sizeof(wchar_t));
    SecureZeroMemory(key.data(), key.size());
    Refresh();

    if (CopyToClipboard(ToCrlf(csrPem))) msg += L"\nCSR 內容已複製到剪貼簿，可以直接貼到 CA 的申請頁面。";
    if (!reuse) msg += L"\n私鑰也已載入到這個工具；拿到 CA 簽發的憑證後拖進來，就會自動配對並組成憑證鏈。";
    Info(msg);
    SetStatus(L"已產生 CSR：" + csrPath);
}

// ---------------------------------------------------------------------------
// 選單
// ---------------------------------------------------------------------------
static HMENU ExportMenu() { return GetSubMenu(GetMenu(g_hwnd), 2); }

static void ShowExportMenu() {
    RECT r;
    GetWindowRect(g_buttons[3], &r);
    TPMPARAMS tpm = {sizeof(tpm), r};
    TrackPopupMenuEx(ExportMenu(), TPM_LEFTALIGN | TPM_TOPALIGN | TPM_VERTICAL, r.left, r.bottom, g_hwnd, &tpm);
}

static void ShowContextMenu(POINT pt) {
    bool has;
    LPARAM p = SelectedParam(&has);
    if (!has) return;
    HMENU m = CreatePopupMenu();
    if (p >= 0) {
        AppendMenuW(m, MF_STRING | MF_DEFAULT, ID_TOOLS_VIEW, L"以 Windows 憑證對話框檢視(&V)");
        AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(m, MF_STRING, ID_EDIT_SETLEAF, L"設為終端憑證(&L)");
        AppendMenuW(m, MF_STRING | (g_ws.leafOverride ? 0 : MF_GRAYED), ID_EDIT_AUTOLEAF, L"自動判斷終端憑證(&A)");
        AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(m, MF_STRING, ID_EXP_SEL_COPY, L"複製這張憑證的 PEM(&C)");
        AppendMenuW(m, MF_STRING, ID_EXP_SEL_PEM, L"匯出這張憑證（PEM）(&P)...");
        AppendMenuW(m, MF_STRING, ID_EXP_SEL_DER, L"匯出這張憑證（DER）(&D)...");
        if (g_ws.certs[p].keyIndex >= 0) AppendMenuW(m, MF_STRING, ID_EXP_SEL_KEY, L"匯出它的私鑰（PEM）(&K)...");
        AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(m, MF_STRING, ID_TOOLS_CSR, L"以這張憑證的內容產生 CSR 或自簽憑證(&G)...");
    } else {
        AppendMenuW(m, MF_STRING, ID_EXP_SEL_KEY, L"匯出這把私鑰（PEM）(&K)...");
    }
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, ID_EDIT_REMOVE, L"移除(&R)\tDel");
    TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_hwnd, nullptr);
    DestroyMenu(m);
}

// ---------------------------------------------------------------------------
// 版面
// ---------------------------------------------------------------------------
static const wchar_t* kButtonText[7] = {L"開啟檔案...", L"貼上 PEM", L"補齊並驗證", L"匯出 ▾", L"移除", L"全部清除", L"產生 CSR / 自簽..."};
static const int kButtonId[7] = {IDC_BTN_OPEN, IDC_BTN_PASTE, IDC_BTN_VALIDATE, IDC_BTN_EXPORT, IDC_BTN_REMOVE, IDC_BTN_CLEAR, IDC_BTN_CSR};
// 畫面上的排列順序（索引對應 g_buttons）；負數代表前面留空
static const int kButtonOrder[] = {0, 1, 2, 3, -1, 6, -1, 4, 5};
static const struct { const wchar_t* name; int width; int fmt; } kColumns[] = {
    {L"#", 36, LVCFMT_RIGHT}, {L"角色", 96, LVCFMT_LEFT}, {L"主體", 230, LVCFMT_LEFT}, {L"簽發者", 210, LVCFMT_LEFT},
    {L"到期日", 92, LVCFMT_LEFT}, {L"狀態", 170, LVCFMT_LEFT}, {L"私鑰", 48, LVCFMT_CENTER}, {L"來源", 170, LVCFMT_LEFT},
};

static int TextWidth(const wchar_t* s) {
    HDC dc = GetDC(g_hwnd);
    HGDIOBJ old = SelectObject(dc, g_font);
    SIZE sz = {};
    GetTextExtentPoint32W(dc, s, (int)wcslen(s), &sz);
    SelectObject(dc, old);
    ReleaseDC(g_hwnd, dc);
    return sz.cx;
}

static void CreateUiFont() {
    if (g_font) DeleteObject(g_font);
    NONCLIENTMETRICSW ncm = {sizeof(ncm)};
    SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0, g_dpi);
    LOGFONTW lf = ncm.lfMessageFont;
    wcscpy_s(lf.lfFaceName, L"Microsoft JhengHei UI");
    g_font = CreateFontIndirectW(&lf);
}

static void Layout() {
    RECT rc;
    GetClientRect(g_hwnd, &rc);
    SendMessageW(g_status, WM_SIZE, 0, 0);
    RECT sr;
    GetWindowRect(g_status, &sr);
    int sh = sr.bottom - sr.top;
    int m = S(8), bh = S(30), x = m, y = m;
    for (int i : kButtonOrder) {
        if (i < 0) {
            x += S(10);
            continue;
        }
        int w = std::max(S(80), TextWidth(kButtonText[i]) + S(28));
        MoveWindow(g_buttons[i], x, y, w, bh, TRUE);
        x += w + S(6);
    }
    const wchar_t* chk = L"匯出時包含根憑證";
    MoveWindow(g_chkRoot, x + S(10), y, TextWidth(chk) + S(30), bh, TRUE);

    int top = y + bh + m;
    int avail = rc.bottom - sh - top - m;
    int listH = std::max(S(120), avail * 42 / 100);
    MoveWindow(g_list, m, top, rc.right - 2 * m, listH, TRUE);
    int dy = top + listH + S(6);
    MoveWindow(g_detail, m, dy, rc.right - 2 * m, std::max(S(60), (int)rc.bottom - sh - m - dy), TRUE);
}

static void ApplyFont() {
    for (HWND h : g_buttons) SendMessageW(h, WM_SETFONT, (WPARAM)g_font, TRUE);
    for (HWND h : {g_chkRoot, g_list, g_detail, g_status}) SendMessageW(h, WM_SETFONT, (WPARAM)g_font, TRUE);
}

static void CreateChildren(HWND hwnd) {
    for (int i = 0; i < (int)_countof(g_buttons); i++)
        g_buttons[i] = CreateWindowExW(0, L"BUTTON", kButtonText[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 0, 0,
                                       hwnd, (HMENU)(INT_PTR)kButtonId[i], g_inst, nullptr);
    g_chkRoot = CreateWindowExW(0, L"BUTTON", L"匯出時包含根憑證", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX, 0, 0, 0, 0,
                                hwnd, (HMENU)IDC_CHK_ROOT, g_inst, nullptr);
    g_list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
                             0, 0, 0, 0, hwnd, (HMENU)IDC_LIST, g_inst, nullptr);
    ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    SetWindowTheme(g_list, L"Explorer", nullptr);
    for (int i = 0; i < (int)_countof(kColumns); i++) {
        LVCOLUMNW col = {LVCF_TEXT | LVCF_WIDTH | LVCF_FMT};
        col.pszText = (LPWSTR)kColumns[i].name;
        col.cx = S(kColumns[i].width);
        col.fmt = kColumns[i].fmt;
        ListView_InsertColumn(g_list, i, &col);
    }
    g_detail = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                               0, 0, 0, 0, hwnd, (HMENU)IDC_DETAIL, g_inst, nullptr);
    SendMessageW(g_detail, EM_SETLIMITTEXT, 4 * 1024 * 1024, 0);
    SendMessageW(g_detail, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(S(6), S(6)));
    g_status = CreateWindowExW(0, STATUSCLASSNAMEW, L"", WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, hwnd, (HMENU)IDC_STATUS, g_inst, nullptr);
    ApplyFont();
}

// ---------------------------------------------------------------------------
// 視窗程序
// ---------------------------------------------------------------------------
static LRESULT OnNotify(NMHDR* nm) {
    if (nm->idFrom != IDC_LIST) return 0;
    switch (nm->code) {
        case LVN_ITEMCHANGED: {
            auto* lv = (NMLISTVIEW*)nm;
            if (!g_filling && (lv->uChanged & LVIF_STATE) && ((lv->uNewState ^ lv->uOldState) & LVIS_SELECTED)) UpdateDetail();
            break;
        }
        case NM_DBLCLK:
            if (SelectedCert() >= 0) OnView();
            break;
        case NM_RCLICK: {
            POINT pt;
            GetCursorPos(&pt);
            ShowContextMenu(pt);
            break;
        }
        case LVN_KEYDOWN: {
            auto* kd = (NMLVKEYDOWN*)nm;
            if (kd->wVKey == VK_DELETE) OnRemove();
            else if (kd->wVKey == VK_RETURN) OnView();
            else if (kd->wVKey == VK_APPS || (kd->wVKey == VK_F10 && GetKeyState(VK_SHIFT) < 0)) {
                int i = ListView_GetNextItem(g_list, -1, LVNI_FOCUSED);
                RECT r = {};
                if (i >= 0) ListView_GetItemRect(g_list, i, &r, LVIR_LABEL);
                POINT pt = {r.left + S(20), r.bottom};
                ClientToScreen(g_list, &pt);
                ShowContextMenu(pt);
            }
            break;
        }
        case NM_CUSTOMDRAW: {
            auto* cd = (NMLVCUSTOMDRAW*)nm;
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                LPARAM p = cd->nmcd.lItemlParam;
                if (p < 0) {
                    cd->clrText = RGB(0xA0, 0x60, 0x00);
                } else if (p < (LPARAM)g_ws.certs.size()) {
                    const OrderEntry* e = EntryOf((int)p);
                    PCCERT_CONTEXT c = g_ws.certs[p].cert.get();
                    if (DaysRemaining(c) < 0 || NotYetValid(c)) cd->clrText = RGB(0xC0, 0x20, 0x20);
                    else if (e && e->issuerMissing) cd->clrText = RGB(0xA0, 0x60, 0x00);
                    else if (e && e->role == Role::Unused) cd->clrText = GetSysColor(COLOR_GRAYTEXT);
                }
                return CDRF_NEWFONT;
            }
            break;
        }
    }
    return 0;
}

static void OnCommand(int id) {
    switch (id) {
        case IDC_BTN_OPEN: case ID_FILE_OPEN: OnOpen(); break;
        case ID_FILE_OPEN_FOLDER: OnOpenFolder(); break;
        case IDC_BTN_PASTE: case ID_EDIT_PASTE: OnPaste(); break;
        case IDC_BTN_VALIDATE: case ID_TOOLS_VALIDATE: OnValidate(); break;
        case IDC_BTN_EXPORT: ShowExportMenu(); break;
        case IDC_BTN_REMOVE: case ID_EDIT_REMOVE: OnRemove(); break;
        case IDC_BTN_CLEAR: case ID_EDIT_CLEAR: OnClear(); break;
        case IDC_BTN_CSR: case ID_TOOLS_CSR: OnCsr(); break;
        case ID_EDIT_SETLEAF: OnSetLeaf(false); break;
        case ID_EDIT_AUTOLEAF: OnSetLeaf(true); break;
        case ID_TOOLS_VIEW: OnView(); break;
        case ID_FILE_EXIT: DestroyWindow(g_hwnd); break;
        case ID_HELP_ABOUT: OnAbout(); break;
        case IDOK:   // IsDialogMessage 會把 Enter 轉成 IDOK
            if (GetFocus() == g_list) OnView();
            break;
        case IDC_CHK_ROOT: break;
        default:
            if (id >= ID_EXP_FULLCHAIN && id <= ID_EXP_SEL_KEY) OnExport(id);
            break;
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            g_hwnd = hwnd;
            g_dpi = GetDpiForWindow(hwnd);
            CreateUiFont();
            CreateChildren(hwnd);
            DragAcceptFiles(hwnd, TRUE);
            Refresh(false);
            return 0;
        case WM_SIZE:
            Layout();
            return 0;
        case WM_GETMINMAXINFO: {
            auto* mmi = (MINMAXINFO*)lp;
            mmi->ptMinTrackSize = {S(820), S(500)};
            return 0;
        }
        case WM_DPICHANGED: {
            UINT old = g_dpi;
            g_dpi = HIWORD(wp);
            CreateUiFont();
            ApplyFont();
            for (int i = 0; i < (int)_countof(kColumns); i++)
                ListView_SetColumnWidth(g_list, i, MulDiv(ListView_GetColumnWidth(g_list, i), (int)g_dpi, (int)old));
            auto* r = (RECT*)lp;
            SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
            Layout();
            return 0;
        }
        case WM_CTLCOLORSTATIC:
            if ((HWND)lp == g_detail) {
                SetBkColor((HDC)wp, GetSysColor(COLOR_WINDOW));
                SetTextColor((HDC)wp, GetSysColor(COLOR_WINDOWTEXT));
                return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
            }
            break;
        case WM_NOTIFY:
            return OnNotify((NMHDR*)lp);
        case WM_COMMAND:
            OnCommand(LOWORD(wp));
            return 0;
        case WM_INITMENUPOPUP: {
            HMENU m = (HMENU)wp;
            bool any = !g_order.empty();
            bool key = LeafKey() != nullptr;
            bool sel = SelectedCert() >= 0;
            for (int id : {ID_EXP_FULLCHAIN, ID_EXP_INTERMEDIATES, ID_EXP_P7B, ID_EXP_PFX, ID_EXP_JKS, ID_EXP_COPY_FULLCHAIN, ID_TOOLS_VALIDATE})
                EnableMenuItem(m, id, MF_BYCOMMAND | (any && !(id == ID_TOOLS_VALIDATE && g_busy) ? MF_ENABLED : MF_GRAYED));
            for (int id : {ID_EXP_CHAIN_KEY, ID_EXP_KEY_PKCS8, ID_EXP_KEY_PKCS1, ID_EXP_KEY_ENC})
                EnableMenuItem(m, id, MF_BYCOMMAND | (key ? MF_ENABLED : MF_GRAYED));
            for (int id : {ID_TOOLS_VIEW, ID_EDIT_SETLEAF}) EnableMenuItem(m, id, MF_BYCOMMAND | (sel ? MF_ENABLED : MF_GRAYED));
            EnableMenuItem(m, ID_EDIT_AUTOLEAF, MF_BYCOMMAND | (g_ws.leafOverride ? MF_ENABLED : MF_GRAYED));
            return 0;
        }
        case WM_DROPFILES: {
            HDROP drop = (HDROP)wp;
            UINT n = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
            std::vector<std::wstring> paths;
            for (UINT i = 0; i < n; i++) {
                wchar_t buf[MAX_PATH * 4];
                if (DragQueryFileW(drop, i, buf, _countof(buf))) paths.push_back(buf);
            }
            DragFinish(drop);
            SetForegroundWindow(hwnd);
            LoadPaths(paths);
            return 0;
        }
        case WM_APP_LOADARGS: {
            int argc = 0;
            LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
            std::vector<std::wstring> paths;
            for (int i = 1; i < argc; i++) paths.push_back(argv[i]);
            LocalFree(argv);
            if (!paths.empty()) LoadPaths(paths);
            return 0;
        }
        case WM_APP_VALIDATED:
            OnValidated((ChainReport*)lp);
            return 0;
        case WM_DESTROY:
            g_ws.Clear();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int show) {
    g_inst = inst;
    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    WNDCLASSEXW wc = {sizeof(wc)};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(IDI_APP));
    wc.hIconSm = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"CertChainToolWnd";
    wc.lpszMenuName = MAKEINTRESOURCEW(IDR_MENU);
    RegisterClassExW(&wc);

    UINT dpi = GetDpiForSystem();
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, kTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                MulDiv(1120, dpi, 96), MulDiv(760, dpi, 96), nullptr, nullptr, inst, nullptr);
    if (!hwnd) return 1;
    // 依實際所在螢幕的 DPI 調整初始大小
    if (g_dpi != dpi) {
        RECT r;
        GetWindowRect(hwnd, &r);
        SetWindowPos(hwnd, nullptr, 0, 0, S(1120), S(760), SWP_NOMOVE | SWP_NOZORDER);
    }
    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);
    PostMessageW(hwnd, WM_APP_LOADARGS, 0, 0);

    HACCEL accel = LoadAcceleratorsW(inst, MAKEINTRESOURCEW(IDR_ACCEL));
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (TranslateAcceleratorW(hwnd, accel, &msg)) continue;
        if (IsDialogMessageW(hwnd, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    CoUninitialize();
    return (int)msg.wParam;
}

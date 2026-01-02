/*
 * WhitebarNative.cpp - Single File C++ Port of Whitebar (XP Compatible /
 * OpenSSL)
 * * Dependencies: MSYS2 OpenSSL
 * pacman -S mingw-w64-x86_64-openssl (or mingw-w64-i686-openssl for 32-bit XP)
 * * Compile with MSYS2/MinGW64:
 * g++ -I/c/Users/Lynden/Downloads/openssl/include
 * -L/c/Users/Lynden/Downloads/openssl FidoNative10_GEMINI.cpp -o WhitebarNative.exe
 * -mconsole -mwindows -static -lssl -lcrypto -lws2_32 -lcomctl32 -lgdi32
 * -lole32 -lrpcrt4 -lcrypt32 -mno-mmx -mno-sse -mno-sse2 -lcomdlg32
 */
#define UNICODE
#define _UNICODE
#define _WIN32_IE 0x0500
#define _WIN32_WINNT 0x0500 // Target Windows XP

// FIX: Winsock2 headers MUST be included before windows.h
#include <winsock2.h>

#include <windows.h>

#include <commctrl.h>
#include <commdlg.h> // Save File Dialog

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// OpenSSL Headers
#include <openssl/err.h>
#include <openssl/ssl.h>
/*
#undef freopen_s
#define freopen_s(pf, fn, mode, stream)                                        \
  ((*(pf) = freopen((fn), (mode), (stream))) ? 0 : errno)
*/
// Link against system libraries (MinGW specific pragma)
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "comctl32")
#pragma comment(lib, "user32")
#pragma comment(lib, "gdi32")
#pragma comment(lib, "rpcrt4")
#pragma comment(lib, "comdlg32")

using namespace std;

// ==========================================
// 0. Helpers & Structs
// ==========================================

struct WindowsEdition {
  wstring Name;
  int Id;
};
struct WindowsRelease {
  wstring Name;
  vector<WindowsEdition> Editions;
};
struct WindowsVersion {
  wstring Name;
  wstring PageType;
  vector<WindowsRelease> Releases;
};
struct WindowsLanguage {
  wstring Name;
  wstring DisplayName;
  int SkuId;
  wstring SessionId;
};
struct DownloadLink {
  wstring Architecture;
  wstring Url;
};

std::atomic<bool> g_appRunning(true);

typedef void (*ProgressCallback)(int percent);

// Simple string conversions
wstring ToWString(const string &s) {
  if (s.empty())
    return L"";
  int size_needed =
      MultiByteToWideChar(CP_UTF8, 0, &s[0], (int)s.size(), NULL, 0);
  wstring wstrTo(size_needed, 0);
  MultiByteToWideChar(CP_UTF8, 0, &s[0], (int)s.size(), &wstrTo[0],
                      size_needed);
  return wstrTo;
}

string ToString(const wstring &w) {
  if (w.empty())
    return "";
  int size_needed = WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), NULL,
                                        0, NULL, NULL);
  string strTo(size_needed, 0);
  WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), &strTo[0], size_needed,
                      NULL, NULL);
  return strTo;
}

// XP-Safe DPI Awareness
void EnableDPI() {
  HMODULE hUser32 = LoadLibraryA("user32.dll");
  if (hUser32) {
    typedef BOOL(WINAPI * SetProcessDPIAware_t)();
    SetProcessDPIAware_t pSetProcessDPIAware =
        (SetProcessDPIAware_t)GetProcAddress(hUser32, "SetProcessDPIAware");
    if (pSetProcessDPIAware)
      pSetProcessDPIAware();
    FreeLibrary(hUser32);
  }
}

// ==========================================
// 1. Networking (OpenSSL + Winsock)
// ==========================================

bool ParseUrl(const string &url, string &host, string &path, bool &isHttps) {
  size_t protocol = url.find("://");
  if (protocol == string::npos)
    return false;

  isHttps = (url.substr(0, 5) == "https");
  size_t hostStart = protocol + 3;
  size_t pathStart = url.find("/", hostStart);

  if (pathStart == string::npos) {
    host = url.substr(hostStart);
    path = "/";
  } else {
    host = url.substr(hostStart, pathStart - hostStart);
    path = url.substr(pathStart);
  }
  return true;
}

// Helper types for dynamic loading of XP+ networking functions (getaddrinfo)
typedef int(WSAAPI *getaddrinfo_t)(const char *, const char *,
                                   const struct addrinfo *, struct addrinfo **);
typedef void(WSAAPI *freeaddrinfo_t)(struct addrinfo *);

getaddrinfo_t p_getaddrinfo = NULL;
freeaddrinfo_t p_freeaddrinfo = NULL;

void LoadNetworking() {
  HMODULE hWs2 = LoadLibraryA("ws2_32.dll");
  if (hWs2) {
    p_getaddrinfo = (getaddrinfo_t)GetProcAddress(hWs2, "getaddrinfo");
    p_freeaddrinfo = (freeaddrinfo_t)GetProcAddress(hWs2, "freeaddrinfo");
  }
}

// Win2k Compatible Host Resolution
// Returns a socket connected to the host/port
SOCKET ConnectToHost(const string &host, bool isHttps) {
  if (p_getaddrinfo) {
    // Modern (XP+) Path
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (p_getaddrinfo(host.c_str(), isHttps ? "443" : "80", &hints, &res) !=
        0) {
      return INVALID_SOCKET;
    }

    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) {
      p_freeaddrinfo(res);
      return INVALID_SOCKET;
    }

    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
      closesocket(sock);
      p_freeaddrinfo(res);
      return INVALID_SOCKET;
    }
    p_freeaddrinfo(res);
    return sock;
  } else {
    // Legacy (Win2k) Path using gethostbyname (IPv4 only)
    struct hostent *he = gethostbyname(host.c_str());
    if (!he)
      return INVALID_SOCKET;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(isHttps ? 443 : 80);
    addr.sin_addr = *((struct in_addr *)he->h_addr);
    memset(&(addr.sin_zero), 0, 8);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
      return INVALID_SOCKET;

    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr)) ==
        SOCKET_ERROR) {
      closesocket(sock);
      return INVALID_SOCKET;
    }
    return sock;
  }
}

// Helper for both API requests and File Downloads
// returns true if success
bool PerformRequest(const string &urlStr, const string &method,
                    const string &referer, string &responseBody,
                    bool downloadToFile, const wstring &filePath,
                    ProgressCallback cb) {
  string currentUrl = urlStr;
  int redirects = 0;

  while (redirects < 5 && g_appRunning) {
    string host, path;
    bool isHttps;
    if (!ParseUrl(currentUrl, host, path, isHttps))
      return false;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
      return false;

    SOCKET sock = ConnectToHost(host, isHttps);
    if (sock == INVALID_SOCKET) {
      WSACleanup();
      return false;
    }

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    if (isHttps) {
      ctx = SSL_CTX_new(TLS_client_method());
      if (!ctx) {
        closesocket(sock);
        WSACleanup();
        return false;
      }
      SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
      ssl = SSL_new(ctx);
      SSL_set_fd(ssl, (int)sock);
      SSL_set_tlsext_host_name(ssl, host.c_str());
      if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(sock);
        WSACleanup();
        return false;
      }
    }

    stringstream req;
    req << method << " " << path << " HTTP/1.1\r\n";
    req << "Host: " << host << "\r\n";
    req << "User-Agent: Mozilla/5.0 Whitebar/1.0\r\n";
    if (!referer.empty())
      req << "Referer: " << referer << "\r\n";
    req << "Connection: close\r\n\r\n";
    string request = req.str();

    if (isHttps)
      SSL_write(ssl, request.c_str(), (int)request.length());
    else
      send(sock, request.c_str(), (int)request.length(), 0);

    // Read Headers
    string headers;
    char buffer[1];
    bool headerDone = false;
    while (true) {
      int r = isHttps ? SSL_read(ssl, buffer, 1) : recv(sock, buffer, 1, 0);
      if (r <= 0)
        break;
      headers += buffer[0];
      if (headers.length() >= 4 &&
          headers.substr(headers.length() - 4) == "\r\n\r\n") {
        headerDone = true;
        break;
      }
    }

    if (!headerDone) { /* cleanup */
      return false;
    }

    // Parse Status Code
    int statusCode = 0;
    size_t firstSpace = headers.find(" ");
    if (firstSpace != string::npos) {
      size_t secondSpace = headers.find(" ", firstSpace + 1);
      if (secondSpace != string::npos) {
        statusCode =
            atoi(headers.substr(firstSpace + 1, secondSpace - firstSpace - 1)
                     .c_str());
      }
    }

    // Handle Redirects
    if (statusCode == 301 || statusCode == 302) {
      size_t locPos = headers.find("\nLocation: ");
      if (locPos == string::npos)
        locPos = headers.find("\nlocation: ");
      if (locPos != string::npos) {
        size_t endLoc = headers.find("\r", locPos);
        currentUrl = headers.substr(locPos + 11, endLoc - (locPos + 11));

        // Cleanup current connection
        if (isHttps) {
          SSL_shutdown(ssl);
          SSL_free(ssl);
          SSL_CTX_free(ctx);
        }
        closesocket(sock);
        WSACleanup();
        redirects++;
        continue; // Loop again with new URL
      }
    }

    // Handle Body
    if (downloadToFile) {
      ofstream outfile(filePath.c_str(), ios::binary);

      // Get Content-Length for progress
      long long totalSize = 0;
      size_t clPos = headers.find("\nContent-Length: ");
      if (clPos != string::npos) {
        totalSize = _atoi64(headers.substr(clPos + 17).c_str());
      }

      char chunk[8192];
      long long downloaded = 0;
      int r;
      int lastPct = -1;
      while ((r = (isHttps ? SSL_read(ssl, chunk, sizeof(chunk))
                           : recv(sock, chunk, sizeof(chunk), 0))) > 0) {
        if (!g_appRunning)
          break;
        outfile.write(chunk, r);
        downloaded += r;

        // Update Progress Callback
        if (cb && totalSize > 0) {
          int pct = (int)((downloaded * 100) / totalSize);
          if (pct != lastPct) {
            cb(pct);
            lastPct = pct;
          }
        }
      }
      outfile.close();
    } else {
      // String response
      char chunk[4096];
      int r;
      while ((r = (isHttps ? SSL_read(ssl, chunk, sizeof(chunk) - 1)
                           : recv(sock, chunk, sizeof(chunk) - 1, 0))) > 0) {
        chunk[r] = 0;
        responseBody.append(chunk, r);
      }
    }

    if (isHttps) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
      SSL_CTX_free(ctx);
    }
    closesocket(sock);
    WSACleanup();
    return true;
  }
  return false;
}

string MakeRequest(const wstring &url, const wstring &referer = L"") {
  string body;
  PerformRequest(ToString(url), "GET", ToString(referer), body, false, L"",
                 NULL);
  return body;
}

// UUID Helper
wstring GenerateGuid() {
  UUID uuid;
  UuidCreate(&uuid);
  RPC_WSTR str;
  UuidToString(&uuid, &str);
  wstring ret = (wchar_t *)str;
  RpcStringFree(&str);
  return ret;
}

// Simple JSON Parsing
// Simple JSON Parsing (Regex)
string ExtractJsonValue(const string &json, const string &key) {
  try {
    regex re("\"" + key + "\":\\s*(\"[^\"]*\"|[0-9\\.]+)");
    smatch match;
    if (regex_search(json, match, re)) {
      string val = match[1].str();
      if (val.length() > 0 && val[0] == '"')
        return val.substr(1, val.length() - 2); // Strip quotes
      return val;
    }
  } catch (...) {
  }
  return "";
}

// XML Parser
// XML Parser (Regex)
wstring ParseArchs(const string &xml) {
  wstring archs = L"";
  try {
    regex re("<arch>(.*?)</arch>");
    auto words_begin = sregex_iterator(xml.begin(), xml.end(), re);
    auto words_end = sregex_iterator();

    bool first = true;
    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
      smatch match = *i;
      string val = match[1].str();
      if (!first)
        archs += L", ";
      archs += ToWString(val);
      first = false;
    }
  } catch (...) {
  }
  return archs.empty() ? L"x64" : archs;
}

// ==========================================
// 1. Data Logic
// ==========================================

class WhitebarClient {
public:
  vector<WindowsVersion> Versions;
  const wstring OrgId = L"y6jn8c31";
  const wstring ProfileId = L"606624d44113";

  WhitebarClient() { InitializeData(); }

  void InitializeData() {
    WindowsVersion w11;
    w11.Name = L"Windows 11";
    w11.PageType = L"windows11";
    WindowsRelease r11;
    r11.Name = L"25H2 (Build 26200.6584 - 2025.10)";
    r11.Editions.push_back({L"Windows 11 Home/Pro/Edu", 3262});
    r11.Editions.push_back({L"Windows 11 Home China", 3263});
    w11.Releases.push_back(r11);
    Versions.push_back(w11);

    WindowsVersion w10;
    w10.Name = L"Windows 10";
    w10.PageType = L"Windows10ISO";
    WindowsRelease r10;
    r10.Name = L"22H2 v1 (Build 19045.2965 - 2023.05)";
    r10.Editions.push_back({L"Windows 10 Home/Pro/Edu", 2618});
    r10.Editions.push_back({L"Windows 10 Home China", 2378});
    w10.Releases.push_back(r10);
    Versions.push_back(w10);

    WindowsVersion uefi22;
    uefi22.Name = L"UEFI Shell 2.2";
    uefi22.PageType = L"UEFI_SHELL 2.2";
    AddUefiRelease(uefi22, L"25H1 (edk2-stable202505)");
    AddUefiRelease(uefi22, L"24H2 (edk2-stable202411)");
    AddUefiRelease(uefi22, L"24H1 (edk2-stable202405)");
    AddUefiRelease(uefi22, L"23H2 (edk2-stable202311)");
    AddUefiRelease(uefi22, L"23H1 (edk2-stable202305)");
    AddUefiRelease(uefi22, L"22H2 (edk2-stable202211)");
    AddUefiRelease(uefi22, L"22H1 (edk2-stable202205)");
    AddUefiRelease(uefi22, L"21H2 (edk2-stable202108)");
    AddUefiRelease(uefi22, L"21H1 (edk2-stable202105)");
    AddUefiRelease(uefi22, L"20H2 (edk2-stable202011)");
    Versions.push_back(uefi22);

    WindowsVersion uefi20;
    uefi20.Name = L"UEFI Shell 2.0";
    uefi20.PageType = L"UEFI_SHELL 2.0";
    AddUefiRelease(uefi20, L"4.632 [20100426]", false);
    Versions.push_back(uefi20);
  }

  void AddUefiRelease(WindowsVersion &ver, wstring name, bool hasDebug = true) {
    WindowsRelease r;
    r.Name = name;
    r.Editions.push_back({L"Release", 0});
    if (hasDebug)
      r.Editions.push_back({L"Debug", 1});
    ver.Releases.push_back(r);
  }

  vector<WindowsLanguage> GetLanguages(const WindowsVersion &ver,
                                       const WindowsEdition &ed) {
    vector<WindowsLanguage> results;
    if (ver.PageType.find(L"UEFI") == 0) {
      results.push_back({L"en-us", L"English (US)", 0, L""});
      return results;
    }
    wstring sessionId = GenerateGuid();
    MakeRequest(L"https://vlscppe.microsoft.com/tags?org_id=" + OrgId +
                L"&session_id=" + sessionId);
    wstring url =
        L"https://www.microsoft.com/software-download-connector/api/"
        L"getskuinformationbyproductedition?profile=" +
        ProfileId + L"&productEditionId=" + to_wstring(ed.Id) +
        L"&SKU=undefined&friendlyFileName=undefined&Locale=en-US&sessionID=" +
        sessionId;
    string json = MakeRequest(url);

    size_t arrayStart = json.find("\"Skus\":[");
    if (arrayStart == string::npos)
      return results;
    size_t current = arrayStart;
    while ((current = json.find("{", current)) != string::npos) {
      size_t endObj = json.find("}", current);
      if (endObj == string::npos)
        break;
      string obj = json.substr(current, endObj - current + 1);
      WindowsLanguage lang;
      lang.SessionId = sessionId;
      string idStr = ExtractJsonValue(obj, "Id");
      if (!idStr.empty()) {
        try {
          lang.SkuId = stoi(idStr);
        } catch (...) {
          continue;
        }
        lang.Name = ToWString(ExtractJsonValue(obj, "Language"));
        lang.DisplayName =
            ToWString(ExtractJsonValue(obj, "LocalizedLanguage"));
        bool exists = false;
        for (const auto &l : results)
          if (l.Name == lang.Name)
            exists = true;
        if (!exists)
          results.push_back(lang);
      }
      current = endObj + 1;
    }
    return results;
  }

  vector<DownloadLink> GetDownloadLinks(const WindowsLanguage &lang,
                                        const WindowsVersion &ver,
                                        const WindowsRelease &rel,
                                        const WindowsEdition &ed) {
    vector<DownloadLink> results;
    if (ver.PageType.find(L"UEFI") == 0) {
      wstring tag = rel.Name.substr(0, rel.Name.find(L' '));
      wstring shellVer = ver.PageType.substr(11);
      wstring baseUrl =
          L"https://github.com/pbatard/UEFI-Shell/releases/download/" + tag;
      wstring isoName = L"/UEFI-Shell-" + shellVer + L"-" + tag;
      isoName += (ed.Id == 0) ? L"-RELEASE.iso" : L"-DEBUG.iso";
      wstring xmlUrl = baseUrl + L"/Version.xml";
      string xml = MakeRequest(xmlUrl);
      DownloadLink link;
      link.Url = baseUrl + isoName;
      link.Architecture = ParseArchs(xml);
      results.push_back(link);
      return results;
    }
    wstring url = L"https://www.microsoft.com/software-download-connector/api/"
                  L"GetProductDownloadLinksBySku?profile=" +
                  ProfileId + L"&productEditionId=undefined&SKU=" +
                  to_wstring(lang.SkuId) +
                  L"&friendlyFileName=undefined&Locale=en-US&sessionID=" +
                  lang.SessionId;
    string json = MakeRequest(
        url, L"https://www.microsoft.com/software-download/windows11");

    size_t arrayStart = json.find("\"ProductDownloadOptions\":[");
    if (arrayStart == string::npos)
      return results;
    size_t current = arrayStart;
    while ((current = json.find("{", current)) != string::npos) {
      size_t endObj = json.find("}", current);
      if (endObj == string::npos)
        break;
      string obj = json.substr(current, endObj - current + 1);
      string typeCode = ExtractJsonValue(obj, "DownloadType");
      if (!typeCode.empty()) {
        DownloadLink link;
        link.Url = ToWString(ExtractJsonValue(obj, "Uri"));
        if (typeCode == "0")
          link.Architecture = L"x86";
        else if (typeCode == "1")
          link.Architecture = L"x64";
        else if (typeCode == "2")
          link.Architecture = L"ARM64";
        else
          link.Architecture = L"Unknown";
        results.push_back(link);
      }
      current = endObj + 1;
    }
    return results;
  }
};

// ==========================================
// 2. GUI Logic
// ==========================================

#define ID_COMBO_VER 101
#define ID_COMBO_REL 102
#define ID_COMBO_ED 103
#define ID_COMBO_LANG 104
#define ID_COMBO_ARCH 105
#define ID_BTN_DOWN 200
#define ID_CHECK_DL 201
#define ID_PROGRESS 300
#define WM_DATA_READY (WM_USER + 1)
#define WM_DOWNLOAD_DONE (WM_USER + 2)

WhitebarClient client;
vector<WindowsRelease> g_releases;
vector<WindowsEdition> g_editions;
vector<WindowsLanguage> g_languages;
vector<DownloadLink> g_links;
HWND hCombos[5];
HWND hBtnDownload, hStatus, hCheckDl, hProgress;
HFONT hFont;

float GetDpiScale() {
  HDC hdc = GetDC(NULL);
  if (!hdc)
    return 1.0f;
  int dpi = GetDeviceCaps(hdc, LOGPIXELSX);
  ReleaseDC(NULL, hdc);
  return dpi / 96.0f;
}
int Scale(int val, float factor) { return (int)(val * factor); }

void PopulateCombo(HWND hCombo, const vector<wstring> &items) {
  SendMessage(hCombo, CB_RESETCONTENT, 0, 0);
  for (const auto &item : items)
    SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)item.c_str());
}
int GetComboIndex(HWND hCombo) {
  return (int)SendMessage(hCombo, CB_GETCURSEL, 0, 0);
}
void ResetCombos(int startIdx) {
  for (int i = startIdx; i < 5; i++) {
    SendMessage(hCombos[i], CB_RESETCONTENT, 0, 0);
    EnableWindow(hCombos[i], FALSE);
  }
  EnableWindow(hBtnDownload, FALSE);
}
void SetStatus(const wstring &text) { SetWindowTextW(hStatus, text.c_str()); }

void OnVerChanged() {
  ResetCombos(1);
  int idx = GetComboIndex(hCombos[0]);
  if (idx < 0)
    return;
  g_releases = client.Versions[idx].Releases;
  vector<wstring> names;
  for (const auto &r : g_releases)
    names.push_back(r.Name);
  PopulateCombo(hCombos[1], names);
  EnableWindow(hCombos[1], TRUE);
}
void OnRelChanged() {
  ResetCombos(2);
  int idx = GetComboIndex(hCombos[1]);
  if (idx < 0)
    return;
  g_editions = g_releases[idx].Editions;
  vector<wstring> names;
  for (const auto &e : g_editions)
    names.push_back(e.Name);
  PopulateCombo(hCombos[2], names);
  EnableWindow(hCombos[2], TRUE);
}
void OnEdChanged(HWND hWnd) {
  ResetCombos(3);
  int verIdx = GetComboIndex(hCombos[0]);
  int edIdx = GetComboIndex(hCombos[2]);
  if (verIdx < 0 || edIdx < 0)
    return;
  SetStatus(L"Fetching Languages...");
  EnableWindow(hCombos[0], FALSE);
  EnableWindow(hCombos[1], FALSE);
  EnableWindow(hCombos[2], FALSE);
  thread([=]() {
    g_languages =
        client.GetLanguages(client.Versions[verIdx], g_editions[edIdx]);
    PostMessage(hWnd, WM_DATA_READY, 1, 0);
  }).detach();
}
void OnLangChanged(HWND hWnd) {
  ResetCombos(4);
  int verIdx = GetComboIndex(hCombos[0]);
  int relIdx = GetComboIndex(hCombos[1]);
  int edIdx = GetComboIndex(hCombos[2]);
  int langIdx = GetComboIndex(hCombos[3]);
  if (langIdx < 0)
    return;
  SetStatus(L"Fetching Links...");
  EnableWindow(hCombos[3], FALSE);
  thread([=]() {
    g_links =
        client.GetDownloadLinks(g_languages[langIdx], client.Versions[verIdx],
                                g_releases[relIdx], g_editions[edIdx]);
    PostMessage(hWnd, WM_DATA_READY, 2, 0);
  }).detach();
}

// Progress Callback wrappers
void GuiProgressCallback(int percent) {
  if (hProgress)
    PostMessage(hProgress, PBM_SETPOS, percent, 0);
}

void CliProgressCallback(int percent) {
  int barWidth = 30;
  cout << "\r[";
  int pos = barWidth * percent / 100;
  for (int i = 0; i < barWidth; ++i) {
    if (i < pos)
      cout << "=";
    else if (i == pos)
      cout << ">";
    else
      cout << " ";
  }
  cout << "] " << percent << " % " << flush;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  switch (msg) {
  case WM_CREATE: {
    float s = GetDpiScale();
    int fontSize = Scale(16, s);
    hFont = CreateFont(fontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    const wchar_t *labels[] = {L"Windows Version:", L"Release:", L"Edition:",
                               L"Language:", L"Architecture:"};
    int marginX = Scale(20, s);
    int currentY = Scale(10, s);
    int comboW = Scale(340, s);
    int stepY = Scale(35, s);

    for (int i = 0; i < 5; i++) {
      HWND hSt = CreateWindow(L"STATIC", labels[i], WS_CHILD | WS_VISIBLE,
                              marginX, currentY, Scale(300, s), Scale(20, s),
                              hWnd, NULL, NULL, NULL);
      SendMessage(hSt, WM_SETFONT, (WPARAM)hFont, TRUE);
      currentY += Scale(20, s);
      hCombos[i] = CreateWindow(
          L"COMBOBOX", L"",
          WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP,
          marginX, currentY, comboW, Scale(200, s), hWnd,
          (HMENU)(uintptr_t)(ID_COMBO_VER + i), NULL, NULL);
      SendMessage(hCombos[i], WM_SETFONT, (WPARAM)hFont, TRUE);
      if (i > 0)
        EnableWindow(hCombos[i], FALSE);
      currentY += stepY;
    }

    // Checkbox
    hCheckDl = CreateWindow(
        L"BUTTON", L"Download to Disk",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP, marginX, currentY,
        Scale(200, s), Scale(20, s), hWnd, (HMENU)ID_CHECK_DL, NULL, NULL);
    SendMessage(hCheckDl, WM_SETFONT, (WPARAM)hFont, TRUE);
    currentY += Scale(25, s);

    // Download Button
    hBtnDownload =
        CreateWindow(L"BUTTON", L"Download",
                     WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
                     marginX, currentY, Scale(150, s), Scale(30, s), hWnd,
                     (HMENU)ID_BTN_DOWN, NULL, NULL);
    SendMessage(hBtnDownload, WM_SETFONT, (WPARAM)hFont, TRUE);
    EnableWindow(hBtnDownload, FALSE);

    // Status
    hStatus = CreateWindow(L"STATIC", L"Ready", WS_CHILD | WS_VISIBLE, marginX,
                           currentY + Scale(40, s), comboW, Scale(20, s), hWnd,
                           NULL, NULL, NULL);
    SendMessage(hStatus, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Progress Bar
    hProgress = CreateWindowEx(0, PROGRESS_CLASS, NULL,
                               WS_CHILD | WS_VISIBLE | PBS_SMOOTH, marginX,
                               currentY + Scale(65, s), comboW, Scale(20, s),
                               hWnd, (HMENU)ID_PROGRESS, NULL, NULL);

    // Init
    vector<wstring> verNames;
    for (const auto &v : client.Versions)
      verNames.push_back(v.Name);
    PopulateCombo(hCombos[0], verNames);
    break;
  }
  case WM_COMMAND: {
    int id = LOWORD(wParam);
    int cmd = HIWORD(wParam);
    if (cmd == CBN_SELCHANGE) {
      if (id == ID_COMBO_VER)
        OnVerChanged();
      else if (id == ID_COMBO_REL)
        OnRelChanged();
      else if (id == ID_COMBO_ED)
        OnEdChanged(hWnd);
      else if (id == ID_COMBO_LANG)
        OnLangChanged(hWnd);
      else if (id == ID_COMBO_ARCH)
        EnableWindow(hBtnDownload, TRUE);
    } else if (id == ID_BTN_DOWN && cmd == BN_CLICKED) {
      int idx = GetComboIndex(hCombos[4]);
      if (idx < 0 || idx >= g_links.size())
        return 0;
      string url = ToString(g_links[idx].Url);

      // Check if Download to Disk is checked
      if (SendMessage(hCheckDl, BM_GETCHECK, 0, 0) == BST_CHECKED) {
        // Save Dialog
        OPENFILENAME ofn = {0};
        wchar_t szFile[260] = {0};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hWnd;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = L"ISO Files\0*.iso\0All Files\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.lpstrDefExt = L"iso";
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

        if (GetSaveFileName(&ofn) == TRUE) {
          wstring filePath = ofn.lpstrFile;
          EnableWindow(hBtnDownload, FALSE);
          EnableWindow(hCheckDl, FALSE);
          for (int i = 0; i < 5; i++)
            EnableWindow(hCombos[i], FALSE);

          SetStatus(L"Downloading... Please wait.");

          thread([=]() {
            string dummy;
            bool success = PerformRequest(url, "GET", "", dummy, true, filePath,
                                          GuiProgressCallback);
            PostMessage(hWnd, WM_DOWNLOAD_DONE, success ? 1 : 0, 0);
          }).detach();
        }
      } else {
        ShellExecuteW(NULL, L"open", g_links[idx].Url.c_str(), NULL, NULL,
                      SW_SHOWNORMAL);
      }
    }
    break;
  }
  case WM_DATA_READY:
    EnableWindow(hCombos[0], TRUE);
    EnableWindow(hCombos[1], TRUE);
    EnableWindow(hCombos[2], TRUE);
    if (wParam == 1) {
      vector<wstring> names;
      for (const auto &l : g_languages)
        names.push_back(l.DisplayName);
      PopulateCombo(hCombos[3], names);
      EnableWindow(hCombos[3], TRUE);
      SetStatus(L"Select Language.");
    } else if (wParam == 2) {
      vector<wstring> archs;
      for (const auto &l : g_links)
        archs.push_back(l.Architecture);
      PopulateCombo(hCombos[4], archs);
      EnableWindow(hCombos[4], TRUE);
      EnableWindow(hCombos[3], TRUE);
      SetStatus(L"Select Architecture.");
    }
    break;
  case WM_DOWNLOAD_DONE:
    EnableWindow(hBtnDownload, TRUE);
    EnableWindow(hCheckDl, TRUE);
    // Re-enable combos based on state (Architecture and lower is surely
    // populated if we downloaded)
    for (int i = 0; i < 5; i++)
      EnableWindow(hCombos[i], TRUE);

    SetStatus(wParam == 1 ? L"Download Complete!" : L"Download Failed.");
    SendMessage(hProgress, PBM_SETPOS, 0, 0);
    if (wParam == 1)
      MessageBox(hWnd, L"Download completed successfully.", L"Success",
                 MB_OK | MB_ICONINFORMATION);
    else
      MessageBox(hWnd, L"Download failed. Check internet connection.", L"Error",
                 MB_OK | MB_ICONERROR);
    break;
  case WM_CTLCOLORSTATIC:
    return (LRESULT)GetStockObject(WHITE_BRUSH);
  case WM_DESTROY:
    g_appRunning = false;
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProc(hWnd, msg, wParam, lParam);
}

// ==========================================
// 3. Entry Point & CLI
// ==========================================

int GetSelection(size_t max) {
  int sel = -1;
  while (true) {
    wcout << L"Select [0-" << max - 1 << L"]: ";
    if (wcin >> sel && sel >= 0 && sel < (int)max)
      return sel;

    if (wcin.fail() && wcin.eof())
      return 0; // Failsafe for broken pipe

    wcout << L"Invalid selection. Try again." << endl;
    wcin.clear();
    wcin.ignore(10000, '\n');
  }
}

// Argument Parsing Helper
map<wstring, wstring> ParseArgs(int argc, LPWSTR *argv) {
  map<wstring, wstring> args;
  for (int i = 1; i < argc; i++) {
    wstring arg = argv[i];
    if (arg[0] == L'-' || arg[0] == L'/') {
      wstring key = arg.substr(1);
      if (key.length() > 0 && key[0] == L'-')
        key = key.substr(1); // Handle --flag
      transform(key.begin(), key.end(), key.begin(), ::tolower);

      if (i + 1 < argc && argv[i + 1][0] != L'-' && argv[i + 1][0] != L'/') {
        args[key] = argv[i + 1];
        i++;
      } else {
        args[key] = L"true"; // Boolean flag
      }
    }
  }
  return args;
}

// Case-insensitive containment check
bool ContainsName(const wstring &source, const wstring &query) {
  wstring s = source;
  wstring q = query;
  transform(s.begin(), s.end(), s.begin(), ::tolower);
  transform(q.begin(), q.end(), q.begin(), ::tolower);
  return s.find(q) != wstring::npos;
}

void RunCLI(int argc, LPWSTR *argv, bool useBrowser) {
  wcout << L"Whitebar CLI" << endl;
  wcout << L"----------------------------------" << endl;

  map<wstring, wstring> args = ParseArgs(argc, argv);
  bool getUrl = args.count(L"geturl");

  // 1. Version
  const WindowsVersion *ver = nullptr;
  if (args.count(L"win")) {
    wstring q = args[L"win"];
    for (const auto &v : client.Versions) {
      if (ContainsName(v.Name, q)) {
        ver = &v;
        wcout << L"Selected Version: " << ver->Name << endl;
        break;
      }
    }
    if (!ver)
      wcout << L"Version '" << q << L"' not found. Falling back to interactive."
            << endl;
  }

  if (!ver) {
    wcout << L"\nAvailable Windows Versions:" << endl;
    for (size_t i = 0; i < client.Versions.size(); i++)
      wcout << L" [" << i << L"] " << client.Versions[i].Name << endl;
    ver = &client.Versions[GetSelection(client.Versions.size())];
  }

  // 2. Release
  const WindowsRelease *rel = nullptr;
  if (args.count(L"rel")) {
    wstring q = args[L"rel"];
    if (ContainsName(L"latest", q) && !ver->Releases.empty()) {
      rel = &ver->Releases[0];
    } else {
      for (const auto &r : ver->Releases) {
        if (ContainsName(r.Name, q)) {
          rel = &r;
          break;
        }
      }
    }
    if (rel)
      wcout << L"Selected Release: " << rel->Name << endl;
    else
      wcout << L"Release '" << q << L"' not found. Falling back to interactive."
            << endl;
  }

  if (!rel) {
    wcout << L"\nAvailable Releases for " << ver->Name << L":" << endl;
    for (size_t i = 0; i < ver->Releases.size(); i++)
      wcout << L" [" << i << L"] " << ver->Releases[i].Name << endl;
    rel = &ver->Releases[GetSelection(ver->Releases.size())];
  }

  // 3. Edition
  const WindowsEdition *ed = nullptr;
  if (args.count(L"ed")) {
    wstring q = args[L"ed"];
    for (const auto &e : rel->Editions) {
      if (ContainsName(e.Name, q)) {
        ed = &e;
        wcout << L"Selected Edition: " << ed->Name << endl;
        break;
      }
    }
    if (!ed)
      wcout << L"Edition '" << q << L"' not found. Falling back to interactive."
            << endl;
  }

  if (!ed) {
    wcout << L"\nAvailable Editions for " << rel->Name << L":" << endl;
    for (size_t i = 0; i < rel->Editions.size(); i++)
      wcout << L" [" << i << L"] " << rel->Editions[i].Name << endl;
    ed = &rel->Editions[GetSelection(rel->Editions.size())];
  }

  // 4. Language
  wcout << L"\nFetching Languages..." << endl;
  auto langs = client.GetLanguages(*ver, *ed);
  if (langs.empty()) {
    wcout << L"No languages found." << endl;
    return;
  }

  const WindowsLanguage *lang = nullptr;
  if (args.count(L"lang")) {
    wstring q = args[L"lang"];
    for (const auto &l : langs) {
      if (ContainsName(l.Name, q) || ContainsName(l.DisplayName, q)) {
        lang = &l;
        wcout << L"Selected Language: " << lang->DisplayName << endl;
        break;
      }
    }
    if (!lang)
      wcout << L"Language '" << q
            << L"' not found. Falling back to interactive." << endl;
  }

  if (!lang) {
    wcout << L"Select Language:" << endl;
    for (size_t i = 0; i < langs.size(); i++)
      wcout << L" [" << i << L"] " << langs[i].DisplayName << endl;
    lang = &langs[GetSelection(langs.size())];
  }

  // 5. Architecture
  wcout << L"\nFetching Links..." << endl;
  auto links = client.GetDownloadLinks(*lang, *ver, *rel, *ed);
  if (links.empty()) {
    wcout << L"No links found." << endl;
    return;
  }

  const DownloadLink *link = nullptr;
  if (args.count(L"arch")) {
    wstring q = args[L"arch"];
    for (const auto &l : links) {
      if (ContainsName(l.Architecture, q)) {
        link = &l;
        wcout << L"Selected Architecture: " << link->Architecture << endl;
        break;
      }
    }
    if (!link)
      wcout << L"Architecture '" << q
            << L"' not found. Falling back to interactive." << endl;
  } else if (links.size() == 1) {
    // Auto-select if only 1 arch exists (often the case)
    link = &links[0];
    wcout << L"Auto-selected Architecture: " << link->Architecture << endl;
  }

  if (!link) {
    wcout << L"Select Architecture:" << endl;
    for (size_t i = 0; i < links.size(); i++)
      wcout << L" [" << i << L"] " << links[i].Architecture << endl;
    link = &links[GetSelection(links.size())];
  }

  if (getUrl) {
    wcout << link->Url << endl;
    return;
  }

  wcout << L"\n--------------------------" << endl;
  wcout << L"URL: " << link->Url << endl;
  wcout << L"--------------------------" << endl;

  if (useBrowser) {
    if (args.empty()) { // Interactive mode pause
      wcout << L"Press Enter to open browser..." << endl;
      wcin.ignore();
      wcin.get();
    } else {
      wcout << L"Opening browser..." << endl;
    }
    ShellExecuteW(NULL, L"open", link->Url.c_str(), NULL, NULL, SW_SHOWNORMAL);
  } else {
    // Direct Download
    string url = ToString(link->Url);
    size_t slash = url.find_last_of("/");
    string fname =
        (slash != string::npos) ? url.substr(slash + 1) : "download.iso";
    // Remove query parameters if present
    size_t q = fname.find("?");
    if (q != string::npos)
      fname = fname.substr(0, q);

    wcout << L"Downloading to: " << ToWString(fname) << endl;
    string dummy;
    bool success = PerformRequest(url, "GET", "", dummy, true, ToWString(fname),
                                  CliProgressCallback);
    cout << endl; // Newline after progress bar
    if (success)
      wcout << L"Download Complete." << endl;
    else
      wcout << L"Download Failed." << endl;

    if (args.empty()) { // Interactive mode pause
      wcout << L"Press Enter to exit..." << endl;
      wcin.ignore();
      wcin.get();
    }
  }
}

bool IsValidFidoFlag(const wchar_t *arg) {
  if (!arg)
    return false;
  const wchar_t *key = arg;
  if (key[0] == L'-' || key[0] == L'/')
    key++;
  if (key[0] == L'-')
    key++;
  const wchar_t *valid[] = {L"win",  L"rel",    L"ed",         L"lang",
                            L"arch", L"geturl", L"use-browser"};
  for (const auto &v : valid) {
    if (lstrcmpiW(key, v) == 0)
      return true;
  }
  return false;
}

// Helper types for dynamic loading of XP+ console functions
typedef BOOL(WINAPI *AttachConsole_t)(DWORD);
typedef DWORD(WINAPI *GetConsoleProcessList_t)(LPDWORD, DWORD);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
  EnableDPI();
  InitCommonControls();
  LoadNetworking();

  // Load XP-only console functions dynamically
  HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
  AttachConsole_t pAttachConsole =
      (AttachConsole_t)GetProcAddress(hKernel32, "AttachConsole");
  GetConsoleProcessList_t pGetConsoleProcessList =
      (GetConsoleProcessList_t)GetProcAddress(hKernel32,
                                              "GetConsoleProcessList");

  int nArgs;
  LPWSTR *argvW = CommandLineToArgvW(GetCommandLineW(), &nArgs);
  bool cliMode = false;
  bool useBrowser = false;

  // Check flags first
  for (int i = 1; i < nArgs; i++) {
    if (lstrcmpiW(argvW[i], L"--use-browser") == 0 ||
        lstrcmpiW(argvW[i], L"/use-browser") == 0) {
      useBrowser = true;
    }
  }

  // Smart Console Handling for -mconsole builds:
  // IF we are in GUI mode (no args) but have a console, check if we own it.
  // If we are the only process in the console list, it was created for us
  // (double-click). We should FreeConsole() to hide it throughout the GUI
  // session.
  // WIN2K FALLBACK: If API missing, just skip this (console remains open on
  // 2k if compiled with -mconsole)
  if (nArgs <= 1 && pGetConsoleProcessList) {
    DWORD pidList[2];
    DWORD num = pGetConsoleProcessList(pidList, 2);
    if (num == 1) {
      FreeConsole();
    }
  }

  if (nArgs > 1) {
    if (lstrcmpiW(argvW[1], L"--cli") == 0 || lstrcmpiW(argvW[1], L"/cli") == 0)
      cliMode = true;
    else if (IsValidFidoFlag(argvW[1]))
      cliMode = true;
    else {
      // For GUI app, we might want to just show a messagebox or ignore
      // invalid args instead of printing to non-existent console
      if (pAttachConsole && pAttachConsole(ATTACH_PARENT_PROCESS)) {
        freopen("CONOUT$", "w", stdout);
        wcout << L"Error: Invalid arguments provided: " << argvW[1] << endl;
      }
      return 1;
    }
  }

  if (cliMode) {
    bool attached = false;
    if (pAttachConsole) {
      attached = pAttachConsole(ATTACH_PARENT_PROCESS);
    }

    bool created = false;

    // If attach failed, we might need a new console.
    // However, if we were launched via -mconsole, we already have one
    // attached! AttachConsole fails with ERROR_ACCESS_DENIED if we are
    // already attached.
    if (!attached) {
      bool alreadyAttached = false;
      if (pAttachConsole && GetLastError() == ERROR_ACCESS_DENIED) {
        alreadyAttached = true;
      }
      // On Win2k, pAttachConsole is null, so we assume we have no parent
      // console to attach to. But we might be in -mconsole mode? Just try
      // AllocConsole if we don't think we are attached.
      if (!alreadyAttached) {
        created = AllocConsole();
      }
    }

    // Redirect streams unconditionally (whether we attached, created, or
    // already had one)
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    freopen("CONIN$", "r", stdin);

    std::ios::sync_with_stdio(true);

    // Clear stream states to ensure they use the new handles
    std::wcout.clear();
    std::cout.clear();
    std::wcerr.clear();
    std::cerr.clear();

    RunCLI(nArgs, argvW, useBrowser);

    // Pause ONLY if we created a new window.
    if (created && !useBrowser) {
      wcout << L"\nPress Enter to exit..." << endl;
      wcin.ignore();
      wcin.get();
    }
    return 0;
  }

  HWND hCon = GetConsoleWindow();
  if (hCon)
    ShowWindow(hCon, SW_HIDE);

  WNDCLASSEX wc = {0};
  wc.cbSize = sizeof(WNDCLASSEX);
  wc.lpfnWndProc = WndProc;
  wc.hInstance = GetModuleHandle(NULL);
  wc.hCursor = LoadCursor(NULL, IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
  wc.lpszClassName = L"WhitebarNativeClass";
  RegisterClassEx(&wc);

  float s = GetDpiScale();
  HWND hWnd = CreateWindow(L"WhitebarNativeClass", L"Whitebar (Native)",
                           WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU |
                               WS_MINIMIZEBOX | WS_VISIBLE,
                           100, 100, Scale(400, s), Scale(630, s), NULL, NULL,
                           GetModuleHandle(NULL), NULL);

  MSG msg;
  while (GetMessage(&msg, NULL, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
  }
  return (int)msg.wParam;
}

// Wrapper for -mconsole users
int main() {
  return WinMain(GetModuleHandle(NULL), NULL, GetCommandLineA(), SW_SHOWNORMAL);
}
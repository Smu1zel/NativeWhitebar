/*
 * NativeWhitebar C API Bridge for Ruflux
 */
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL NativeWhitebar_Init(void);
BOOL NativeWhitebar_ShowGUI(HWND hParent);
BOOL NativeWhitebar_GetDownloadUrl(const char* version, const char* release, const char* edition, const char* language, const char* arch, char* out_url, size_t out_url_size);
BOOL NativeWhitebar_DownloadISO(const char* version, const char* release, const char* edition, const char* language, const char* arch, const char* out_path, void (*progress_cb)(int percent));
void NativeWhitebar_Cancel(void);

#ifdef __cplusplus
}
#endif

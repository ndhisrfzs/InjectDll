#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>

BOOL LoadRemoteDll(LPCWSTR lpszProcessName, LPCWSTR lpszLibName);
BOOL UnLoadRemoteDll(LPCWSTR lpszProcessName, LPCWSTR lpszLibName);

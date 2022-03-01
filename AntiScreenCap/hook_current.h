#pragma once
#include <Windows.h>
#include <string>

bool Is64BitOS();
bool ZwCreateThreadExInjectDll(HANDLE hProcess, const wchar_t* pszDllFileName);
bool HookCurWindow(const std::wstring& dllPath);
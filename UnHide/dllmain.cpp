// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <Shlwapi.h>
#pragma comment(lib,"shlwapi.lib")
using namespace std;

void OutputErrorString(const char* text, const char* file, int line)
{
	char msg[512] = { 0 };
	sprintf(msg, "[%s:%d] %s:%d", file, line, text, GetLastError());
	OutputDebugStringA(msg);
}

string getProcName()
{
	char szProcName[MAX_PATH] = { 0 };
	if (GetModuleFileNameA(NULL, szProcName, MAX_PATH))
	{
		PathStripPathA(szProcName);
		return szProcName;
	}
	else
	{
		OutputErrorString("GetModuleFileNameA failed", __FILE__, __LINE__);
	}
	return string{ "false" };
}
string procName = getProcName();
BOOL CALLBACK lpEnumFunc(HWND hwnd, LPARAM lParam)
{
	DWORD  processId;
	GetWindowThreadProcessId(hwnd, &processId);
	if (processId == GetCurrentProcessId())
	{
		if ((GetWindowLong(hwnd, GWL_STYLE) & WS_VISIBLE) == WS_VISIBLE && SetWindowDisplayAffinity(hwnd, WDA_NONE))
		{
			//获取窗口标题
			char title[MAX_PATH] = { 0 };
			GetWindowTextA(hwnd, title, MAX_PATH);

			//判断最小化
			RECT rect;
			bool haveRect = false, isMinimized = false;
			if (GetClientRect(hwnd, &rect))
			{
				haveRect = (rect.right - rect.left > 0) && (rect.bottom - rect.top > 0);
				isMinimized = !haveRect;
			}

			//summary
			char summary[512] = { 0 };
			sprintf(summary, "进程名:%s, 窗口句柄:%x, 标题:%s, 最小化:%d, 状态:显示", procName.c_str(), (DWORD)hwnd, title, isMinimized);//bool isMinimized不能转成%s
			OutputDebugStringA(summary);
		}
	}
	return TRUE;
}

void setDAForWindows() {
	string procName = getProcName();

	HWND windowHandle = NULL;
	do {
		windowHandle = FindWindowEx(NULL, windowHandle, NULL, NULL);
		if ((GetWindowLong(windowHandle, GWL_STYLE) & WS_VISIBLE) == WS_VISIBLE && SetWindowDisplayAffinity(windowHandle, WDA_NONE))
		{
			//获取窗口标题
			char title[MAX_PATH] = { 0 };
			GetWindowTextA(windowHandle, title, MAX_PATH);

			//判断最小化
			RECT rect;
			bool haveRect = false, isMinimized = false;
			if (GetClientRect(windowHandle, &rect))
			{
				haveRect = (rect.right - rect.left > 0) && (rect.bottom - rect.top > 0);
				isMinimized = !haveRect;
			}
		
			//summary
			char summary[512] = { 0 };
			sprintf(summary, "进程名:%s, 窗口句柄:%x, 标题:%s, 最小化:%d, 状态:显示", procName.c_str(), windowHandle, title, isMinimized);//bool isMinimized不能转成%s
			OutputDebugStringA(summary);
		}

	} while (windowHandle);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		OutputDebugStringA(("----------------Enter " + getProcName() + " ----------------").c_str());
		setDAForWindows();
		//EnumWindows(lpEnumFunc, NULL);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		OutputDebugStringA(("----------------Leave " + getProcName() + " ----------------").c_str());
		break;
	}
    return FALSE;
}


#include "pch.h"
#include "dllmain.h"
#include <iostream>
#include <string>
#include <unordered_map>
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

unordered_map<HWND, char> hastryHookedProc;

LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    // 一般来说，所有运行的进程(有窗口过程的)都会加载这个钩子过程了
    CWPSTRUCT* pCwp = reinterpret_cast<CWPSTRUCT*>(lParam);
    switch (pCwp->message)
    {
    case WM_CREATE:
    {
        if (hastryHookedProc.find(pCwp->hwnd) == hastryHookedProc.end())
        {
            if (SetWindowDisplayAffinity(pCwp->hwnd, WDA_MONITOR))
            {
                char title[MAX_PATH] = { 0 };
                GetWindowTextA(pCwp->hwnd, title, MAX_PATH);
                char msg[512] = { 0 };
                if (title[0] != '\0')
                    sprintf(msg, "WM_CREATE[%s]:%s", procName.c_str(), title);
                else
                    sprintf(msg, "WM_CREATE[%s]:%s", procName.c_str(), "NoTitle");
                OutputDebugStringA(msg);
            }
            hastryHookedProc[pCwp->hwnd] = 1;
        }
        break;
    }
    case WM_SHOWWINDOW:
    {
        if (hastryHookedProc.find(pCwp->hwnd) == hastryHookedProc.end())
        {
            if (SetWindowDisplayAffinity(pCwp->hwnd, WDA_MONITOR))
            {
                char title[MAX_PATH] = { 0 };
                GetWindowTextA(pCwp->hwnd, title, MAX_PATH);
                char msg[512] = { 0 };
                if (title[0] != '\0')
                    sprintf(msg, "WM_SHOWWINDOW[%s]:%s", procName.c_str(), title);
                else
                    sprintf(msg, "WM_SHOWWINDOW[%s]:%s", procName.c_str(), "NoTitle");
                OutputDebugStringA(msg);
            }
            hastryHookedProc[pCwp->hwnd] = 1;
        }
        break;
    }
    /*case WM_CLOSE:
    {
        char title[MAX_PATH] = { 0 };
        GetWindowTextA(pCwp->hwnd, title, MAX_PATH);
        OutputDebugStringA((string(pname) + title + " close").c_str());
        break;
    }*/
    
    default:
        break;
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

EXPORT BOOL WINAPI SetHook(BOOL isInstall)
{
    if (isInstall)
    {
        hHook = SetWindowsHookEx(WH_CALLWNDPROC, HookProc, hInstance, 0);
        if (hHook) OutputDebugStringA("SetWindowsHookEx Success");
        return hHook != NULL;
    }
    else
    {
        if (UnhookWindowsHookEx(hHook))
        {
            OutputDebugStringA("UnhookWindowsHookEx Success");
            hHook = NULL;
            hInstance = NULL;
            return TRUE;
        }
    }
    return FALSE;
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //OutputDebugStringA(("进入:" + procName).c_str());
        hInstance = (HINSTANCE)hModule;
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        //OutputDebugStringA(("离开:" + procName).c_str());
        break;
    }
    return TRUE;
}


#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <Windows.h>
#include <tlhelp32.h>
using namespace std;
enum class LogLevel
{
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
};


void Log(LogLevel level, int line, const char* format, ...);
//void LogW(LogLevel level, int line, const wchar_t* format, ...);

#define COND_LOG_RET(cond, line, formatInfo, msgInfo, code)    \
if (cond)Log(LogLevel::LOG_INFO, line, formatInfo, msgInfo);    \
else{   \
    Log(LogLevel::LOG_ERROR, line, (string(formatInfo) + ", Error: %d").c_str(), msgInfo, GetLastError());    \
    return code;   \
}

#define HANDLE_LOG_RET(handle, line, formatInfo, msgInfo, code)    \
if (handle != INVALID_HANDLE_VALUE && handle != NULL)Log(LogLevel::LOG_INFO, line, formatInfo, msgInfo);    \
else{   \
    Log(LogLevel::LOG_ERROR, line, (string(formatInfo) + ", Error: %d").c_str(), msgInfo, GetLastError());    \
    return code;   \
}

bool FileExists(std::wstring& filePath);

std::wstring getFullFilePath(const std::wstring& filename);

bool HookRtlWindow(bool hook);

//std::string getProcNameById(DWORD pid)
//{
//    PROCESSENTRY32 pe32;
//    // 在使用这个结构之前，先设置它的大小
//    pe32.dwSize = sizeof(PROCESSENTRY32);
//    // 给系统内的所有进程拍一个快照
//    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//    if (hProcessSnap == INVALID_HANDLE_VALUE)
//    {
//        Log(LogLevel::LOG_ERROR, __LINE__, "CreateToolhelp32Snapshot调用失败！: %d", GetLastError());
//        return std::string{};
//    }
//    // 遍历进程快照，轮流显示每个进程的信息
//    BOOL bMore = Process32First(hProcessSnap, &pe32);
//    while (bMore)
//    {
//        if (pe32.th32ProcessID == pid)
//        {
//            std::wstring exeName = std::wstring(pe32.szExeFile);
//            CloseHandle(hProcessSnap);
//            return std::string(exeName.begin(), exeName.end());
//        }
//        bMore = Process32Next(hProcessSnap, &pe32);
//    }
//    // 不要忘记清除掉snapshot对象
//    CloseHandle(hProcessSnap);
//    return std::string{};
//}
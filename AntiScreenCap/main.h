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
//    // ��ʹ������ṹ֮ǰ�����������Ĵ�С
//    pe32.dwSize = sizeof(PROCESSENTRY32);
//    // ��ϵͳ�ڵ����н�����һ������
//    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//    if (hProcessSnap == INVALID_HANDLE_VALUE)
//    {
//        Log(LogLevel::LOG_ERROR, __LINE__, "CreateToolhelp32Snapshot����ʧ�ܣ�: %d", GetLastError());
//        return std::string{};
//    }
//    // �������̿��գ�������ʾÿ�����̵���Ϣ
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
//    // ��Ҫ���������snapshot����
//    CloseHandle(hProcessSnap);
//    return std::string{};
//}
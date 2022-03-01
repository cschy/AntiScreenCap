#define _CRT_SECURE_NO_WARNINGS

#include "hook_current.h"
#include "main.h"
#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <Shlwapi.h>
#pragma comment(lib,"shlwapi.lib")
using namespace std;

typedef BOOL(WINAPI* pfnSetHook) (BOOL);
pfnSetHook SetHook = NULL;

const int FILEMAP_BUF = 64;
const int LOG_SIZE = 512;

//for ipc
char* pBuf;
HANDLE hServerEvent, hClientEvent, hFileMap;
//for save console origin color
WORD wOldColorAttrs;


#ifdef _WIN64
const std::wstring hideDllName{ L"Hide.dll" };
const std::wstring unhideDllName{ L"Unhide.dll" };
const std::wstring RtlHideDllName{L"RtlHide.dll"};
#else
const std::wstring hideDllName{ L"Hide32.dll" };
const std::wstring unhideDllName{ L"Unhide32.dll" };
const std::wstring RtlHideDllName{ L"RtlHide32.dll" };
#endif

//添加MessageBoxTimeout支持
typedef int (WINAPI *MessageBoxTimeoutA)(IN HWND hWnd, IN LPCSTR lpText, IN LPCSTR lpCaption, IN UINT uType, IN WORD wLanguageId, IN DWORD dwMilliseconds);
typedef int (WINAPI *MessageBoxTimeoutW)(IN HWND hWnd, IN LPCWSTR lpText, IN LPCWSTR lpCaption, IN UINT uType, IN WORD wLanguageId, IN DWORD dwMilliseconds);

HMODULE hUser32 = LoadLibraryA("user32.dll");
#ifdef UNICODE
#define MessageBoxTimeout ((MessageBoxTimeoutW)(GetProcAddress(hUser32, "MessageBoxTimeoutW")))
#else
#define MessageBoxTimeout ((MessageBoxTimeoutA)(GetProcAddress(hUser32, "MessageBoxTimeoutA")))
#endif

BOOL WINAPI ConsoleHandler(DWORD CEvent)
{
    switch (CEvent)
    {
    case CTRL_CLOSE_EVENT://close消息有限时机制
        HookRtlWindow(false);
        MessageBoxTimeout(NULL, L"关闭实时窗口注入", L"step 1", MB_OK, 0, 1000);//MessageBox(NULL, L"关闭实时窗口注入", L"step 1", MB_OK);
        Sleep(1500);
        HookCurWindow(unhideDllName);
        MessageBox(NULL, L"还原当前所有窗口", L"step 2", MB_OK);//MessageBoxTimeout(NULL, L"还原当前所有窗口", L"step 2", MB_OK, 0, 1500);
        break;
    case CTRL_C_EVENT:
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        break; 
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT: 
    default:
        return FALSE;
    }
    return TRUE;
}

bool SetPrivilege()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES NewState;
    LUID luidPrivilegeLUID;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) || !LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidPrivilegeLUID))
    {
        Log(LogLevel::LOG_WARN, __LINE__, "SetPrivilege Error: %d", GetLastError());
        return false;
    }
    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Luid = luidPrivilegeLUID;
    NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &NewState, NULL, NULL, NULL))
    {
        Log(LogLevel::LOG_WARN, __LINE__, "AdjustTokenPrivilege Error: %d", GetLastError());
        return false;
    }
    return true;
}

bool initFoundSet()
{
    SetPrivilege();

    CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE_LOG_RET(hStd, __LINE__, "GetStdHandle: %x", hStd, false);
    COND_LOG_RET(GetConsoleScreenBufferInfo(hStd, &csbiInfo), __LINE__, "GetConsoleScreenBufferInfo: %x", csbiInfo.wAttributes, false);
    wOldColorAttrs = csbiInfo.wAttributes;

    COND_LOG_RET(SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE), __LINE__, "SetConsoleCtrlHandler: %x", ConsoleHandler, false);
    return true;
}

void SetConsoleColor(WORD wAttributes)
{
    HANDLE hCon = GetStdHandle(STD_OUTPUT_HANDLE); //获取缓冲区句柄
    if (wAttributes == 0)
        SetConsoleTextAttribute(hCon, wOldColorAttrs);
    else
        SetConsoleTextAttribute(hCon, wAttributes); 
}

void Log(LogLevel level, int line, const char* format, ...)
{
    char msg[LOG_SIZE] = {0};

    va_list ap;
    int ret = -1;
    va_start(ap, format);
    ret = vsprintf(msg, format, ap);
    va_end(ap);

    switch (level)
    {
    case LogLevel::LOG_INFO:
        cout << msg << endl;
        break;
    case LogLevel::LOG_WARN:
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        cout << "[Line " << line << "]  " << msg << endl;
        SetConsoleColor(0);
        break;
    case LogLevel::LOG_ERROR:
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        cout << "[Line " << line << "]  " << msg << endl;
        SetConsoleColor(0);
        break;
    
    default:
        SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        cout << "No this LOG_LEVEL" << endl;
        SetConsoleColor(0);
        break;
    }
}

//bool Exec(const wstring& fullPath, const wstring& param, DWORD dwMilliseconds)
//{
//    SHELLEXECUTEINFO ShExecInfo = { 0 };
//    {
//        ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NO_CONSOLE;
//        ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);							//结构大小
//        ShExecInfo.lpVerb = _T("runas");										//指定该函数的执行动作，以管理员方式运行
//        ShExecInfo.nShow = SW_HIDE;												//隐藏窗口
//        ShExecInfo.lpFile = fullPath.c_str();											//卸载程序路径
//        ShExecInfo.lpParameters = param.c_str();										//卸载程序参数
//    }
//    if (ShellExecuteEx(&ShExecInfo))
//    {
//        if (ShExecInfo.hProcess)
//        {
//            switch (WaitForSingleObject(ShExecInfo.hProcess, dwMilliseconds))
//            {
//            case WAIT_OBJECT_0:		//The state of the specified object is signaled.
//                LogW(LogLevel::LOG_INFO, __LINE__, L"执行程序%s成功", fullPath);
//                return true;
//            case WAIT_TIMEOUT:		//The time-out interval elapsed, and the object's state is nonsignaled.
//                LogW(LogLevel::LOG_ERROR, __LINE__, L"执行程序%s超时", fullPath);
//                break;
//            case WAIT_FAILED:		//Waiting on an invalid handle causes WaitForSingleObject to return WAIT_FAILED.
//                LogW(LogLevel::LOG_ERROR, __LINE__, L"执行程序%s错误: %d", fullPath, GetLastError());
//                break;
//            }
//        }
//        else
//        {
//            LogW(LogLevel::LOG_ERROR, __LINE__, L"执行程序%s句柄异常: %d", fullPath, GetLastError());
//        }
//    }
//    else
//    {
//        LogW(LogLevel::LOG_ERROR, __LINE__, L"执行程序%s失败: %d", fullPath, GetLastError());
//    }
//    return false;
//}

bool FileExists(std::wstring& filePath)
{
    DWORD dwAttrib = GetFileAttributes(filePath.c_str());
    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

std::wstring getFullFilePath(const std::wstring& filename) {
    wchar_t fullPath[MAX_PATH] = {0};
    GetModuleFileName(NULL, fullPath, MAX_PATH);
    PathRemoveFileSpec(fullPath);
    PathAppend(fullPath, filename.c_str());
    std::wstring strFullPath{ fullPath };
    COND_LOG_RET(FileExists(strFullPath), __LINE__, "FileExists: %S", strFullPath.c_str(), std::wstring{});
    return strFullPath;
};

bool HookRtlWindow(bool hook)
{
    if (HMODULE RtlHideDll = LoadLibrary(RtlHideDllName.c_str()); RtlHideDll)
    {
#ifdef _WIN64
        SetHook = (pfnSetHook)GetProcAddress(RtlHideDll, "SetHook");
#else
        SetHook = (pfnSetHook)GetProcAddress(RtlHideDll, "_SetHook@4");
#endif
        if (SetHook)
        {
            if (hook)
            {
                if (SetHook(TRUE))
                {
                    Log(LogLevel::LOG_INFO, __LINE__, "Set Hook Success");
                    return true;
                }
                else
                {
                    Log(LogLevel::LOG_ERROR, __LINE__, "Set Hook Error. See More in DebugView");
                }
            }
            else
            {
                if (SetHook(FALSE))
                {
                    Log(LogLevel::LOG_INFO, __LINE__, "Set Unhook Success");
                    return true;
                }
                else
                {
                    Log(LogLevel::LOG_ERROR, __LINE__, "Set Unhook Error. See More in DebugView");
                }
            }
            
        }
        else
        {
            Log(LogLevel::LOG_ERROR, __LINE__, "GetProcAddress SetHook Error: %d", GetLastError());
        }
    }
    else
    {
        Log(LogLevel::LOG_ERROR, __LINE__, "LoadLibrary %S Error: %d", RtlHideDllName.c_str(), GetLastError());
    }
    return false;
}

struct HandleName
{
    HANDLE handle;
    string name;
};
struct ShareMemory {
    HANDLE hFileMap;
    char* pShareBuf;
    void clear() {
        if (pShareBuf) UnmapViewOfFile(pShareBuf);
        CloseHandle(hFileMap);
    }
};
struct IPC {
    IPC(string fullName, int bufSize = 32, DWORD ms = 5000) :
        sFullExeName(fullName), iBufSize(bufSize), dwMilliseconds(ms) {}
    void clear() {
        fileMap.clear();
        CloseHandle(serverEvent.handle);
        CloseHandle(clientEvent.handle);
    }
    const string sFullExeName;
    HandleName serverEvent, clientEvent;
    //HandleName fileMap;
    ShareMemory fileMap;
    DWORD dwMilliseconds;
    const int iBufSize;
    string sCmd;
};

bool __SetEvent(HANDLE hEvent)
{
    return SetEvent(hEvent);
}
bool __SetEvent(const string& eventName)
{
    HANDLE hEvent = OpenEventA(SYNCHRONIZE, FALSE, eventName.c_str());
    return hEvent && __SetEvent(hEvent);
}
bool __GetEvent(HANDLE hEvent, DWORD dwMilliseconds)
{
    switch (WaitForSingleObject(hEvent, dwMilliseconds))					//同步等待事件受信
    {
    case WAIT_OBJECT_0:		//The state of the specified object is signaled.
        Log(LogLevel::LOG_INFO, __LINE__, "等待事件受信成功(lim:%dms): %x", dwMilliseconds, hEvent);
        return true;
    case WAIT_TIMEOUT:		//The time-out interval elapsed, and the object's state is nonsignaled.
        Log(LogLevel::LOG_INFO, __LINE__, "等待事件受信超时(lim:%dms): %x", dwMilliseconds, hEvent);
        return false;
    case WAIT_FAILED:		//Waiting on an invalid handle causes WaitForSingleObject to return WAIT_FAILED.
        Log(LogLevel::LOG_INFO, __LINE__, "等待事件受信失败: %d", GetLastError());
        return false;
    default:
        break;
    }
    return false;
}
bool __GetEvent(const string& eventName, DWORD dwMilliseconds)
{
    HANDLE hEvent = OpenEventA(SYNCHRONIZE, FALSE, eventName.c_str());
    return hEvent && __GetEvent(hEvent, dwMilliseconds);
}

HANDLE CreateGlobalEvent(string& eventName)
{
    SECURITY_ATTRIBUTES sa;
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = NULL;
    sa.nLength = sizeof(sa);
    if (eventName.find("Global\\") == eventName.npos)
    {
        eventName = "Global\\" + eventName;
    }
    return CreateEventA(&sa, FALSE, FALSE, eventName.c_str());
}

HANDLE CreateGlobalFileMap(string& fileMapName)
{
    if (fileMapName.find("Global\\") == fileMapName.npos)
    {
        fileMapName = "Global\\" + fileMapName;
    }
    return CreateFileMappingA(
        INVALID_HANDLE_VALUE,   //物理文件句柄，设为INVALID_HANDLE_VALUE（无效句柄）以创建一个进程间共享的对象
        NULL,				    //默认安全级别
        PAGE_READWRITE,         //权限可读可写
        0,						//高位文件大小
        FILEMAP_BUF,			//低位文件大小
        fileMapName.c_str()		//共享内存名
    );
}

bool initIPCEnvironment()
{
    string baseName = to_string(GetCurrentProcessId());
    string serverEventName = baseName + "-ServerEvent";
    string clientEventName = baseName + "-ClientEvent";
    string fileMapName = baseName + "-FileMap";
    //服务端信号
    hServerEvent = CreateGlobalEvent(serverEventName);
    COND_LOG_RET(hServerEvent, __LINE__, "CreateGlobalEvent: %s", serverEventName.c_str(), 1);
    //客户端信号
    hClientEvent = CreateGlobalEvent(clientEventName);
    COND_LOG_RET(hClientEvent, __LINE__, "CreateGlobalEvent: %s", clientEventName.c_str(), 1);

    //1.创建共享文件句柄 hMapFile，CreateFileMapping()函数创建一个文件映射内核对象
    hFileMap = CreateGlobalFileMap(fileMapName);
    COND_LOG_RET(hFileMap, __LINE__, "CreateGlobalFileMap: %s", fileMapName.c_str(), 1);

    //2.获取指向文件视图的指针 pBuf，MapViewOfFile()函数负责把文件数据映射到进程的地址空间
    pBuf = (char*)MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, FILEMAP_BUF);
    COND_LOG_RET(pBuf, __LINE__, "MapViewOfFile: %x", pBuf, 1);

    /*strcpy_s(pBuf, FILEMAP_BUF, "hello");
    COND_LOG_RET(SetEvent(hServerEvent), __LINE__, "SetEvent: %s", serverEventName.c_str(), 1);*/

    return true;
}

int main()
{
    COND_LOG_RET(initFoundSet(), __LINE__, "initFoundSet()(ZeroSuccess): %d", GetLastError(), 1);

    COND_LOG_RET(initIPCEnvironment(), __LINE__, "initIPCEnvironment()(ZeroSuccess): %d", GetLastError(), 1);
    
    COND_LOG_RET(HookCurWindow(hideDllName), __LINE__, "HookCurWindow(hideDllName)(ZeroSuccess): %d", GetLastError(), 1);

    COND_LOG_RET(HookRtlWindow(true), __LINE__, "HookRtlWindow(true)(ZeroSuccess): %d", GetLastError(), 1);
    
    strcpy_s(pBuf, FILEMAP_BUF, "hello");
    COND_LOG_RET(SetEvent(hServerEvent), __LINE__, "SetEvent: %x", hServerEvent, 1);

    Log(LogLevel::LOG_INFO, __LINE__, "主线程开始监听与Service通信...");

    while (1)
    {
        __GetEvent(hClientEvent, INFINITE);
        if (pBuf)
        {
            Log(LogLevel::LOG_INFO, __LINE__, "收到控制信息: %s", pBuf);
            if (string(pBuf) == "stop")
            {
                break;
            }
            else if (string(pBuf) == "debug")//显示本身控制台程序
            {
                ShowWindow(GetConsoleWindow(), SW_SHOWNA);
                /*DWORD lasterror = GetLastError();
                auto getLogDir = []() ->string {
                    char dir[MAX_PATH];
                    GetModuleFileNameA(NULL, dir, MAX_PATH);
                    PathRemoveFileSpecA(dir);
#ifdef _WIN64
                    PathAppendA(dir, "log.txt");
#else
                    PathAppendA(dir, "log32.txt");
#endif
                    return string{ dir };
                };
                auto dir = getLogDir();
                if (!dir.empty())
                {
                    FILE* fp = NULL;
                    if ((fp = fopen(dir.c_str(), "a+")) != NULL)
                    {
                        fprintf(fp, "ShowWindow %x ret[%d]: %d\n", (DWORD)consoleWindow, lasterror, ret);
                        fclose(fp);
                    }
                    
                }*/
                __SetEvent(hServerEvent);
            }
        }
    }
    COND_LOG_RET(HookRtlWindow(false), __LINE__, "HookRtlWindow(false)(ZeroSuccess): %d", GetLastError(), 1);
    Sleep(1500);
    COND_LOG_RET(HookCurWindow(unhideDllName), __LINE__, "HookCurWindow(unhideDllName)(ZeroSuccess): %d", GetLastError(), 1);
    __SetEvent(hServerEvent);
    //释放资源
    CloseHandle(hServerEvent);
    CloseHandle(hClientEvent);
    if (pBuf) UnmapViewOfFile(pBuf);
    CloseHandle(hFileMap);
    return 0;
}
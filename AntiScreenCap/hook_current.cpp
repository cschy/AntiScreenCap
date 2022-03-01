#define _CRT_SECURE_NO_WARNINGS

#include "main.h"
#include "hook_current.h"
#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <psapi.h>
#include <Shlwapi.h>
#include <tchar.h>
#include <unordered_map>
#include <list>
#include <Winternl.h>

#pragma comment(lib,"shlwapi.lib")
using namespace std;

bool Is64BitOS()
{
	SYSTEM_INFO sysInfo = { 0 };
	GetNativeSystemInfo(&sysInfo);
	if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
		|| sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
	{
		return true;
	}
	return false;
}
bool is64BitOS = Is64BitOS();

string getProcNameByHandle(HANDLE hProcess)
{
	char exeName[MAX_PATH] = { 0 };
	if (GetModuleFileNameExA(hProcess, NULL, exeName, MAX_PATH))
	{
		PathStripPathA(exeName);
		return exeName;
	}
	Log(LogLevel::LOG_WARN, __LINE__, "getProcNameByHandle GetModuleFileNameExA Error: %d", GetLastError());
	return {};
}

unordered_map<DWORD, string> getSuspendProcess()
{
	unordered_map<DWORD, string> suspendProcess;
	typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);
	pfnNtQuerySystemInformation NtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQuerySystemInformation");

	LPVOID dwBufferProcess = 0;         //接收数据的缓冲区
	DWORD dwBufferProcessSize = 0;      //需要接收的数据的缓冲区大小
	NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwBufferProcessSize);
	dwBufferProcess = new BYTE[dwBufferProcessSize + 0x10000]();    //为了防止进程/线程信息发生突变，多申请0x10000内存(64K)
	LPVOID dwOldBufferProcess = dwBufferProcess;                    //保存缓冲区地址                                       
	NtQuerySystemInformation(SystemProcessInformation, dwBufferProcess, dwBufferProcessSize + 0x10000, &dwBufferProcessSize);

	while (TRUE)
	{
		LPVOID dwAddress = dwBufferProcess;
		dwBufferProcess = (BYTE*)dwBufferProcess + sizeof(SYSTEM_PROCESS_INFORMATION);
		PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)dwAddress;

		int suspendThreads = 0;
		for (DWORD i = 0; i < processInfo->NumberOfThreads; i++)
		{
			//检测进程状态和导致此状态的原因
			if (((SYSTEM_THREAD_INFORMATION*)dwBufferProcess)->ThreadState == 5 && ((SYSTEM_THREAD_INFORMATION*)dwBufferProcess)->WaitReason == 5)
			{
				suspendThreads++;
			}
			dwBufferProcess = (BYTE*)dwBufferProcess + sizeof(SYSTEM_THREAD_INFORMATION);                  //指向此进程的下一个线程结构	
		}
		if (suspendThreads == processInfo->NumberOfThreads)
		{
			wstring wstrName{ processInfo->ImageName.Buffer };
			suspendProcess[(DWORD)(processInfo->UniqueProcessId)] = string(wstrName.begin(), wstrName.end());
		}
		dwBufferProcess = ((BYTE*)dwAddress + ((SYSTEM_PROCESS_INFORMATION*)dwAddress)->NextEntryOffset);				//指向下一个进程
		if (((SYSTEM_PROCESS_INFORMATION*)dwAddress)->NextEntryOffset == 0)							//遍历完成结束
			break;
	}
	delete[] dwOldBufferProcess;      //释放内存    
	return suspendProcess;
}

struct ProcessInfo
{
	string name;
	bool isSuspend;
};

unordered_map<DWORD, ProcessInfo> getProcessInfo()
{
	unordered_map<DWORD, ProcessInfo> processInfoMap;
	typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);
	pfnNtQuerySystemInformation NtQuerySystemInformation = (pfnNtQuerySystemInformation)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQuerySystemInformation");

	LPVOID dwBufferProcess = 0;         //接收数据的缓冲区
	DWORD dwBufferProcessSize = 0;      //需要接收的数据的缓冲区大小
	NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwBufferProcessSize);
	dwBufferProcess = new BYTE[dwBufferProcessSize + 0x10000]();    //为了防止进程/线程信息发生突变，多申请0x10000内存(64K)
	LPVOID dwOldBufferProcess = dwBufferProcess;                    //保存缓冲区地址                                       
	NtQuerySystemInformation(SystemProcessInformation, dwBufferProcess, dwBufferProcessSize + 0x10000, &dwBufferProcessSize);

	while (TRUE)
	{
		LPVOID dwAddress = dwBufferProcess;
		dwBufferProcess = (BYTE*)dwBufferProcess + sizeof(SYSTEM_PROCESS_INFORMATION);
		PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)dwAddress;
		
		int suspendThreads = 0;
		for (DWORD i = 0; i < processInfo->NumberOfThreads; i++)
		{
			//检测进程状态和导致此状态的原因
			if (((SYSTEM_THREAD_INFORMATION*)dwBufferProcess)->ThreadState == 5 && ((SYSTEM_THREAD_INFORMATION*)dwBufferProcess)->WaitReason == 5)
			{
				suspendThreads++;
			}
			dwBufferProcess = (BYTE*)dwBufferProcess + sizeof(SYSTEM_THREAD_INFORMATION);                  //指向此进程的下一个线程结构	
		}

		if ((DWORD)(processInfo->UniqueProcessId) > 0)
		{
			wstring	wstrName = processInfo->ImageName.Buffer;
			bool isSuspend = (suspendThreads == processInfo->NumberOfThreads);
			processInfoMap[(DWORD)(processInfo->UniqueProcessId)] = { string(wstrName.begin(), wstrName.end()), isSuspend };
		}

		dwBufferProcess = ((BYTE*)dwAddress + ((SYSTEM_PROCESS_INFORMATION*)dwAddress)->NextEntryOffset);				//指向下一个进程
		if (((SYSTEM_PROCESS_INFORMATION*)dwAddress)->NextEntryOffset == 0)							//遍历完成结束
			break;
	}
	delete[] dwOldBufferProcess;      //释放内存    
	return processInfoMap;
}

bool ZwCreateThreadExInjectDll(HANDLE hProcess, const wchar_t* pszDllFileName)
{
	int pathSize = (wcslen(pszDllFileName) + 1) * sizeof(wchar_t);

	// 2.在目标进程中申请空间
	LPVOID lpPathAddr = VirtualAllocEx(hProcess, 0, pathSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NULL == lpPathAddr)
	{
		Log(LogLevel::LOG_ERROR, __LINE__, "在目标进程中申请空间失败！：%d", GetLastError());
		CloseHandle(hProcess);
		return false;
	}
	// 3.在目标进程中写入Dll路径
	if (FALSE == WriteProcessMemory(hProcess, lpPathAddr, pszDllFileName, pathSize, NULL)) // 实际写入大小
	{
		Log(LogLevel::LOG_ERROR, __LINE__, "在目标进程中写入Dll路径失败！：%d", GetLastError());
		CloseHandle(hProcess);
		return false;
	}
	// 4.加载ntdll.dll
	HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (NULL == hNtdll)
	{
		Log(LogLevel::LOG_ERROR, __LINE__, "加载ntdll.dll失败！：%d", GetLastError());
		CloseHandle(hProcess);
		return false;
	}
	// 5.获取LoadLibraryA的函数地址
	// FARPROC可以自适应32位与64位
	HMODULE hmKernel32 = LoadLibrary(_T("Kernel32.dll"));
	if (NULL == hmKernel32)
	{
		Log(LogLevel::LOG_ERROR, __LINE__, "加载Kernel32.dll失败！：%d", GetLastError());
		CloseHandle(hProcess);
		return false;
	}
	FARPROC pFuncProcAddr = GetProcAddress(hmKernel32, "LoadLibraryW");
	if (NULL == pFuncProcAddr)
	{
		Log(LogLevel::LOG_ERROR, __LINE__, "获取LoadLibrary函数地址失败！：%d", GetLastError());
		CloseHandle(hProcess);
		return false;
	}
	// 6.获取ZwCreateThreadEx函数地址,该函数在32位与64位下原型不同
	// _WIN64用来判断编译环境，_WIN32用来判断是否是Windows系统
#ifdef _WIN64
	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		ULONG CreateThreadFlags,
		SIZE_T ZeroBits,
		SIZE_T StackSize,
		SIZE_T MaximumStackSize,
		LPVOID pUnkown
		);
#else
	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		BOOL CreateSuspended,
		DWORD dwStackSize,
		DWORD dw1,
		DWORD dw2,
		LPVOID pUnkown
		);
#endif 
	typedef_ZwCreateThreadEx ZwCreateThreadEx = (typedef_ZwCreateThreadEx)GetProcAddress(hNtdll, "ZwCreateThreadEx");
	if (NULL == ZwCreateThreadEx)
	{
		Log(LogLevel::LOG_ERROR, __LINE__, "获取ZwCreateThreadEx函数地址失败！：%d", GetLastError());
		CloseHandle(hProcess);
		return false;
	}
	// 7.在目标进程中创建远线程
	HANDLE hRemoteThread = NULL;
	DWORD dwStatus = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL,
		hProcess, (LPTHREAD_START_ROUTINE)pFuncProcAddr, lpPathAddr, 0, 0, 0, 0, NULL);
	if (NULL == hRemoteThread)
	{
		Log(LogLevel::LOG_ERROR, __LINE__, "目标进程中创建线程失败！：%d", GetLastError());
		CloseHandle(hProcess);
		return false;
	}
	// 8.等待线程结束
	DWORD reason = WaitForSingleObject(hRemoteThread, INFINITE);
	/*if (reason == WAIT_TIMEOUT)
	{
		if (string name = getProcNameByHandle(hProcess); !name.empty())
			Log(LogLevel::LOG_WARN, __LINE__, "WaitForRemoteThreadExit TIMEOUT(2s), Process May Be Suspend: %s", name.c_str());
		else
			Log(LogLevel::LOG_WARN, __LINE__, "WaitForRemoteThreadExit TIMEOUT(2s), Process May Be Suspend: %d", GetProcessId(hProcess));
	}*/
	// 9.清理环境
	VirtualFreeEx(hProcess, lpPathAddr, 0, MEM_RELEASE); //MEM_RELEASE
	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);
	FreeLibrary(hNtdll);
	return true;
}

//bool HookCurWindow(const std::wstring& dllPath)
//{
//	Log(LogLevel::LOG_INFO, __LINE__, ">>>>>>>>>>>>>>>>HOOK CURRENT WINDOWS<<<<<<<<<<<<<<<<");
//	std::wstring DllPath{ getFullFilePath(dllPath) };
//	COND_LOG_RET(!DllPath.empty(), __LINE__, "DllPath.empty(): %d", GetLastError(), false);
//
//	unordered_map<DWORD, ProcessInfo> processInfoMap = getProcessInfo();
//	for (auto i : processInfoMap)
//	{
//		Log(LogLevel::LOG_INFO, __LINE__, "Ready To Inject: %s", i.second.name.c_str());
//		if (i.second.isSuspend)
//		{
//			Log(LogLevel::LOG_WARN, __LINE__, "This is a suspend process: %s", i.second.name.c_str());
//			continue;
//		}
//		// 1.打开目标进程, 不敢用高级的OpenProcess API, 怕类似CSRSS进程蓝屏
//		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, i.first);
//		if (hProcess) {
//			BOOL procIs32bit;
//			/*64-bit process on 64-bit Windows : FALSE
//			32-bit process on 64-bit Windows : TRUE
//			32-bit process on 32-bit Windows : FALSE*/
//			if (IsWow64Process(hProcess, &procIs32bit)) {
//#ifdef _WIN64
//				if (!procIs32bit && is64BitOS) {
//					if (ZwCreateThreadExInjectDll(hProcess, DllPath.c_str())) {
//						Log(LogLevel::LOG_INFO, __LINE__, "Hook Window Success: %s", i.second.name.c_str());
//					}
//					else {
//						Log(LogLevel::LOG_WARN, __LINE__, "Hook Window Failed: %s", i.second.name.c_str());
//					}
//				}
//				else {
//					Log(LogLevel::LOG_WARN, __LINE__, "It's a 32 app: %s", i.second.name.c_str());
//				}
//#else
//				if (procIs32bit || (!procIs32bit && !is64BitOS)) {
//					if (ZwCreateThreadExInjectDll(hProcess, DllPath.c_str())) {
//						Log(LogLevel::LOG_INFO, __LINE__, "Hook Window Success: %s", i.second.name.c_str());
//					}
//					else {
//						Log(LogLevel::LOG_WARN, __LINE__, "Hook Window Failed: %s", i.second.name.c_str());
//					}
//				}
//				else {
//					Log(LogLevel::LOG_WARN, __LINE__, "It's a 64 app: %s", i.second.name.c_str());
//				}
//#endif
//			}
//			else {
//				Log(LogLevel::LOG_ERROR, __LINE__, "判断目标进程是否是64位系统中的32位程序失败: %d", GetLastError());
//				continue;
//			}
//		}
//		else {
//			Log(LogLevel::LOG_WARN, __LINE__, "打开目标进程: %s, 失败: %d", i.second.name.c_str(), GetLastError());
//			continue;
//		}
//	}
//	Log(LogLevel::LOG_INFO, __LINE__, ">>>>>>>>>>>>>>>>HOOK CURRENT WINDOW END<<<<<<<<<<<<<<<<<<");
//	return true;
//}

bool HookCurWindow(const std::wstring& dllPath)
{
	Log(LogLevel::LOG_INFO, __LINE__, ">>>>>>>>>>>>>>>>HOOK CURRENT WINDOWS<<<<<<<<<<<<<<<<");
	std::wstring DllPath{ getFullFilePath(dllPath) };
	COND_LOG_RET(!DllPath.empty(), __LINE__, "DllPath.empty(): %d", GetLastError(), false);
	
	unordered_map<DWORD, string> suspendProc = getSuspendProcess();
	for (auto i : suspendProc)
	{
		Log(LogLevel::LOG_INFO, __LINE__, "suspend process: %s", i.second.c_str());
	}
	unordered_map<DWORD, char> tryHookedProc;//存已注入过的PID
	vector<string> goodHookedProc;//存成功hook的进程名
	HWND windowHandle = NULL;
	do {
		windowHandle = FindWindowEx(NULL, windowHandle, NULL, NULL);
		DWORD dwPid;
		if (GetWindowThreadProcessId(windowHandle, &dwPid)) {
			if (tryHookedProc.find(dwPid) == tryHookedProc.end()) {
				tryHookedProc[dwPid] = 1;
				
				if (suspendProc.find(dwPid) != suspendProc.end())
				{
					Log(LogLevel::LOG_WARN, __LINE__, "This is a suspend process: %s", suspendProc[dwPid].c_str());
					continue;
				}
				// 0.提权
				// 1.打开目标进程, 用高级的OpenProcess API
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
				if (hProcess) {
					string exeName = getProcNameByHandle(hProcess);
					exeName = (!exeName.empty() ? exeName : "Unknow ProcName");
					
					BOOL procIs32bit;
					/*64-bit process on 64-bit Windows : FALSE
					32-bit process on 64-bit Windows : TRUE
					32-bit process on 32-bit Windows : FALSE*/
					if (IsWow64Process(hProcess, &procIs32bit)) {
#ifdef _WIN64
						if (!procIs32bit && is64BitOS) {
							if (ZwCreateThreadExInjectDll(hProcess, DllPath.c_str())) {
								Log(LogLevel::LOG_INFO, __LINE__, "Hook Window For: %s", exeName.c_str());
								goodHookedProc.push_back(exeName);
							}
							else
								Log(LogLevel::LOG_WARN, __LINE__, "Hook Window Failed: %s", exeName.c_str());
						}
						else {
							Log(LogLevel::LOG_WARN, __LINE__, "It's a 32 app: %s", exeName.c_str());
						}
#else
						if (procIs32bit || (!procIs32bit && !is64BitOS)) {
							Log(LogLevel::LOG_INFO, __LINE__, "ready inject: %s", exeName.c_str());
							if (ZwCreateThreadExInjectDll(hProcess, DllPath.c_str())) {
								Log(LogLevel::LOG_INFO, __LINE__, "Hook Window For: %s", exeName.c_str());
								goodHookedProc.push_back(exeName);
							}
							else
								Log(LogLevel::LOG_WARN, __LINE__, "Hook Window Failed: %s", exeName.c_str());
						}
						else {
							Log(LogLevel::LOG_WARN, __LINE__, "It's a 64 app: %s", exeName.c_str());
						}
#endif
						
					}
					else {
						Log(LogLevel::LOG_ERROR, __LINE__, "判断目标进程是否是64位系统中的32位程序失败: %d", GetLastError());
						continue;
					}
				}
				else {
					Log(LogLevel::LOG_WARN, __LINE__, "打开目标进程: %d, 失败: %d", dwPid, GetLastError());
					continue;
				}
			}
			else {
				//cout << "已注入过" << endl;
				continue;
			}
		}
		else {
			Log(LogLevel::LOG_WARN, __LINE__, "GetWindowThreadProcessId Error：%d, HWND: %x", GetLastError(), windowHandle);
		}
	} while (windowHandle);
	//Summary
	Log(LogLevel::LOG_INFO, __LINE__, ">>>>>>>>>>>>>>>>HOOK CURRENT WINDOW END<<<<<<<<<<<<<<<<<<");
	Log(LogLevel::LOG_INFO, __LINE__, "Summary:");
	for (auto& i : goodHookedProc)
	{
		Log(LogLevel::LOG_INFO, __LINE__, i.c_str());
	}
	return true;
}
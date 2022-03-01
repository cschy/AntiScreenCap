#pragma once
#include <windows.h>
#define EXPORT extern "C" __declspec(dllexport)

#pragma data_seg ("shared")
HHOOK hHook = NULL;
HINSTANCE hInstance = NULL;
#pragma data_seg ()
#pragma comment (linker, "/section:shared,rws")

EXPORT BOOL WINAPI SetHook(BOOL isInstall);
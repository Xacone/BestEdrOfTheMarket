// dllmain.cpp : Définit le point d'entrée de l'application DLL.
#include "pch.h"
#include <Windows.h>
#include <wininet.h>

#pragma comment(lib, "WinINet.lib")

__declspec(dllexport) LPVOID _hVirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
) { 
    MessageBoxA(NULL, "VirtualAlloc intercepted ! ", "VirtualAlloc intercepted ! ", MB_ICONINFORMATION);

    return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

__declspec(dllexport) LPVOID _hVirtualAllocEx(
    HANDLE hProcess, 
    LPVOID lpAddress, 
    SIZE_T dwSize, 
    DWORD  flAllocationType, 
    DWORD  flProtect
) {
    MessageBoxA(NULL, "VirtualAllocEx intercepted ! ", "VirtualAllocEx intercepted ! ", MB_ICONINFORMATION);
    
    return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

__declspec(dllexport) LPVOID _hHeapAlloc(
    HANDLE hHeap,
    DWORD dwFlags,
    SIZE_T dwBytes
) {
    MessageBoxA(NULL, "HeapAlloc intercepted ! ", "HeapAlloc intercepted ! ", MB_ICONINFORMATION);

    return HeapAlloc(hHeap, dwFlags, dwBytes);
}

__declspec(dllexport) BOOL _hHeapFree(
    HANDLE hHeap,
    DWORD dwFlags,
    LPVOID lpMem
) {
    MessageBoxA(NULL, "HeapFree intercepted ! ", "HeapFree intercepted ! ", MB_ICONINFORMATION);

    return HeapFree(hHeap, dwFlags, lpMem);
}

__declspec(dllexport) HANDLE _hGetCurrentProcess() {
    MessageBoxA(NULL, "GetCurrentProcess intercepted ! ", "GetCurrentProcess intercepted ! ", MB_ICONINFORMATION);

    return GetCurrentProcess();
}

__declspec(dllexport) BOOL _hReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead
) {
    MessageBoxA(NULL, "ReadProcessMemory intercepted ! ", "ReadProcessMemory intercepted ! ", MB_ICONINFORMATION);

    return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

__declspec(dllexport) HMODULE _hGetModuleHandleA(
    LPCSTR lpModuleName
) {
    MessageBoxA(NULL, "GetModuleHandleA intercepted ! ", "GetModuleHandleA intercepted ! ", MB_ICONINFORMATION);

    return GetModuleHandleA(lpModuleName);
}

__declspec(dllexport) FARPROC _hGetProcAddress(
    HMODULE hModule,
    LPCSTR lpProcName
) {
    MessageBoxA(NULL, "GetProcAddress intercepted ! ", "GetProcAddress intercepted ! ", MB_ICONINFORMATION);

    return GetProcAddress(hModule, lpProcName);
}

__declspec(dllexport) HMODULE _hLoadLibraryA(
    LPCSTR lpLibFileName
) {
    MessageBoxA(NULL, "LoadLibraryA intercepted ! ", "LoadLibraryA intercepted ! ", MB_ICONINFORMATION);

    return LoadLibraryA(lpLibFileName);
}

__declspec(dllexport) HLOCAL _hLocalFree(
    HLOCAL hMem
) {
    MessageBoxA(NULL, "LocalFree intercepted ! ", "LocalFree intercepted ! ", MB_ICONINFORMATION);

    return LocalFree(hMem);
}

__declspec(dllexport) SIZE_T _hVirtualQuery(
    LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T dwLength
) {
    MessageBoxA(NULL, "VirtualQuery intercepted ! ", "VirtualQuery intercepted ! ", MB_ICONINFORMATION);

    return VirtualQuery(lpAddress, lpBuffer, dwLength);
}

__declspec(dllexport) VOID _hRtlCaptureContext(
    PCONTEXT lpContext
) {
    MessageBoxA(NULL, "RtlCaptureContext intercepted ! ", "RtlCaptureContext intercepted ! ", MB_ICONINFORMATION);

    RtlCaptureContext(lpContext);
}

__declspec(dllexport) PRUNTIME_FUNCTION _hRtlLookupFunctionEntry(
    DWORD64 ControlPc,
    PDWORD64 ImageBase,
    PUNWIND_HISTORY_TABLE HistoryTable
) {
    MessageBoxA(NULL, "RtlLookupFunctionEntry intercepted ! ", "RtlLookupFunctionEntry intercepted ! ", MB_ICONINFORMATION);

    return RtlLookupFunctionEntry(ControlPc, ImageBase, HistoryTable);
}

__declspec(dllexport) BOOL _hIsDebuggerPresent() {
    MessageBoxA(NULL, "IsDebuggerPresent intercepted ! ", "IsDebuggerPresent intercepted ! ", MB_ICONINFORMATION);

    return IsDebuggerPresent();
}

__declspec(dllexport) DWORD _hGetCurrentThreadId() {
    MessageBoxA(NULL, "GetCurrentThreadId intercepted ! ", "GetCurrentThreadId intercepted ! ", MB_ICONINFORMATION);

    return GetCurrentThreadId();
}

__declspec(dllexport) HANDLE _hOpenProcess(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
) {
    MessageBoxA(NULL, "OpenProcess intercepted ! ", "OpenProcess intercepted ! ", MB_ICONINFORMATION);

    return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

__declspec(dllexport) BOOL _hWriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
) {
    MessageBoxA(NULL, "WriteProcessMemory intercepted ! ", "WriteProcessMemory intercepted ! ", MB_ICONINFORMATION);

    return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

__declspec(dllexport) HINTERNET _hInternetOpenW(
    LPCWSTR lpszAgent,
    DWORD dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD dwFlags
) {
    MessageBoxA(NULL, "InternetOpenW intercepted ! ", "InternetOpenW intercepted ! ", MB_ICONINFORMATION);

    return InternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

__declspec(dllexport) HINTERNET _hInternetOpenUrlW(
    HINTERNET hInternet,
    LPCWSTR lpszUrl,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    DWORD dwFlags,
    DWORD_PTR dwContext
) {
    MessageBoxA(NULL, "InternetOpenUrlW intercepted ! ", "InternetOpenUrlW intercepted ! ", MB_ICONINFORMATION);

    return InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

__declspec(dllexport) BOOL _hInternetReadFile(
    HINTERNET hFile,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
) {
    MessageBoxA(NULL, "InternetReadFile intercepted ! ", "InternetReadFile intercepted ! ", MB_ICONINFORMATION);

    return InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


#include "pch.h"
#include <Windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <wininet.h>
#include <sstream>    

#pragma comment (lib, "dbghelp.lib")
#pragma comment(lib, "WinINet.lib")

static BOOL(WINAPI* OriginalWriteProcessMemory)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
    ) = WriteProcessMemory;

static BOOL(WINAPI* OriginalReadProcessMemory)(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesRead
) = ReadProcessMemory;

static LPVOID(WINAPI* OriginalVirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
 ) = VirtualAlloc;

static LPVOID(WINAPI* OriginalVirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
) = VirtualAllocEx;

static LPVOID(WINAPI* OriginalHeapAlloc)(
	HANDLE hHeap,
	DWORD dwFlags,
	SIZE_T dwBytes
) = HeapAlloc;

static BOOL(WINAPI* OriginalHeapFree)(
	HANDLE hHeap,
	DWORD dwFlags,
	LPVOID lpMem
) = HeapFree;

static HMODULE(WINAPI* OriginalGetModuleHandleA)(
	LPCSTR lpLibFileName
) = GetModuleHandleA;

static HMODULE(WINAPI* OriginalLoadLibraryA)(
	LPCSTR lpLibFileName
) = LoadLibraryA;

static HLOCAL(WINAPI* OriginalLocalFree)(
	HLOCAL hMem
) = LocalFree;

static SIZE_T(WINAPI* OriginalVirtualQuery)(
	LPCVOID lpAddress,
	PMEMORY_BASIC_INFORMATION lpBuffer,
	SIZE_T dwLength
) = VirtualQuery;

static BOOL(WINAPI* OriginalVirtualFree)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  dwFreeType
) = VirtualFree;

static HINTERNET(WINAPI* OriginalInternetOpenUrlW)(
	HINTERNET hInternet,
	LPCWSTR lpszUrl,
	LPCWSTR lpszHeaders,
	DWORD dwHeadersLength,
	DWORD dwFlags,
	DWORD_PTR dwContext
) = InternetOpenUrlW;

static BOOL(WINAPI* OriginalInternet)(
	HINTERNET hFile,
	LPVOID lpBuffer,
	DWORD dwNumberOfBytesToRead,
	LPDWORD lpdwNumberOfBytesRead
) = InternetReadFile;

static HINTERNET(WINAPI* OriginalInternetOpenW)(
	LPCWSTR lpszAgent,
	DWORD dwAccessType,
	LPCWSTR lpszProxy,
	LPCWSTR lpszProxyBypass,
	DWORD dwFlags
) = InternetOpenW;

static BOOL(WINAPI* OriginalVirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) = VirtualProtect;

static BOOL(WINAPI* OriginalVirtualProtectEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) = VirtualProtectEx;

void sendMsgThroughBeotmNamedPipe(const char* data, SIZE_T size) {
    HANDLE hPipe;
    DWORD bytesWritten;

    hPipe = CreateFile(L"\\\\.\\pipe\\beotm_ch3",
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (hPipe == INVALID_HANDLE_VALUE) {
        //std::cerr << "[!] Failed to open named pipe. Error code: " << GetLastError() << std::endl;
        return;
    }

    if (!WriteFile(hPipe, data, size, &bytesWritten, nullptr)) {
        //std::cerr << "[!] Failed to write to named pipe. Error code: " << GetLastError() << std::endl;
        CloseHandle(hPipe);
        return;
    }

    CloseHandle(hPipe);
}

std::string lpvoidToString(LPVOID lpAddress) {
    std::stringstream ss;
    ss << std::uppercase << std::hex << reinterpret_cast<uintptr_t>(lpAddress);
    return ss.str();
}

std::string formatToJson_ss(const char* functionName, const char* data) {
    std::ostringstream oss;
    oss << "{ ";
    oss << "\"Function\": \"" << functionName << "\", ";
    oss << "\"StringData\": " << " \" " << data << " \" ";
    oss << "}";
    return oss.str();
}

__declspec(dllexport) LPVOID _hVirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
) { 
    
    std::string out = formatToJson_ss((char*)"VirtualAlloc", lpvoidToString(lpAddress).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

__declspec(dllexport) BOOL _hVirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
) {
	std::string out = formatToJson_ss((char*)"VirtualProtect", lpvoidToString(lpAddress).c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

	return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

__declspec(dllexport) BOOL _hVirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
) {
	std::string out = formatToJson_ss((char*)"VirtualProtectEx", lpvoidToString(lpAddress).c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

	return VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

__declspec(dllexport) LPVOID _hVirtualAllocEx(
    HANDLE hProcess, 
    LPVOID lpAddress, 
    SIZE_T dwSize, 
    DWORD  flAllocationType, 
    DWORD  flProtect
) {
    std::string out = formatToJson_ss((char*)"VirtualAllocEx", lpvoidToString((LPVOID)&lpAddress).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

__declspec(dllexport) LPVOID _hHeapAlloc(
    HANDLE hHeap,
    DWORD dwFlags,
    SIZE_T dwBytes
) {

    std::string out = formatToJson_ss((char*)"HeapFree", lpvoidToString(hHeap).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return HeapAlloc(hHeap, dwFlags, dwBytes);
}

__declspec(dllexport) BOOL _hHeapFree(
    HANDLE hHeap,
    DWORD dwFlags,
    LPVOID lpMem
) {

    std::string out = formatToJson_ss((char*)"HeapFree", lpvoidToString(hHeap).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return HeapFree(hHeap, dwFlags, lpMem);
}


__declspec(dllexport) BOOL _hReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead
) {
    
    std::string out = formatToJson_ss((char*)"ReadProcessMemory", lpvoidToString((LPVOID)lpBuffer).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

__declspec(dllexport) HMODULE _hLoadLibraryA(
    LPCSTR lpLibFileName
) {
   
    std::string out = formatToJson_ss((char*)"LoadLibraryA", lpvoidToString((LPVOID)lpLibFileName).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());
    
    return LoadLibraryA(lpLibFileName);
}

__declspec(dllexport) HLOCAL _hLocalFree(
    HLOCAL hMem
) {
    
    std::string out = formatToJson_ss((char*)"LocalFree", lpvoidToString((LPVOID)hMem).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return LocalFree(hMem);
}

__declspec(dllexport) SIZE_T _hVirtualQuery(
    LPCVOID lpAddress,
    PMEMORY_BASIC_INFORMATION lpBuffer,
    SIZE_T dwLength
) {

    std::string out = formatToJson_ss((char*)"VirtualQuery", lpvoidToString((LPVOID)lpAddress).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return VirtualQuery(lpAddress, lpBuffer, dwLength);
}

__declspec(dllexport) BOOL _hWriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
) {

    std::string out = formatToJson_ss((char*)"WriteProcessMemory", lpvoidToString((LPVOID)lpBuffer).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

__declspec(dllexport) HINTERNET _hInternetOpenW(
    LPCWSTR lpszAgent,
    DWORD dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD dwFlags
) {

    std::string out = formatToJson_ss((char*)"InternetOpenW", lpvoidToString((LPVOID)lpszAgent).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

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

    std::string out = formatToJson_ss((char*)"InternetOpenUrlW", lpvoidToString((LPVOID)lpszUrl).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

__declspec(dllexport) BOOL _hInternetReadFile(
    HINTERNET hFile,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
) {
    
    std::string out = formatToJson_ss((char*)"InternetReadFile", lpvoidToString((LPVOID)lpBuffer).c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalInternet(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}


void hookIatTableEntry(PVOID* origin, PVOID target) {
    DWORD oldProtect = 0;

    if (!VirtualProtect(origin, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
        exit(-21);
    }

    *origin = target;

    if (!VirtualProtect(origin, sizeof(PVOID), oldProtect, &oldProtect)) {
        exit(-23);
    }
}


void initHooks() {

    HMODULE baseAddress = GetModuleHandle(NULL);
    ULONG size;

    PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(baseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, NULL);
    
    while (importTbl->OriginalFirstThunk != 0) {

        const char* dllName = (const char*)((BYTE*)baseAddress + importTbl->Name);
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + importTbl->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pFunc = (PIMAGE_THUNK_DATA)((BYTE*)baseAddress + importTbl->FirstThunk);

        while (pThunk->u1.AddressOfData != 0) {

            if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {

                PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((BYTE*)baseAddress + pThunk->u1.AddressOfData);

                if (!strcmp(pImport->Name, "WriteProcessMemory")) {
                    hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hWriteProcessMemory);
                }

                if (!strcmp(pImport->Name, "ReadProcessMemory")) {
                    hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hReadProcessMemory);
                }

                if (!strcmp(pImport->Name, "VirtualAlloc")) {
					hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hVirtualAlloc);
				}

                if (!strcmp(pImport->Name, "VirtualAllocEx")) {
                    hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hVirtualAllocEx);
                }

                if (!strcmp(pImport->Name, "VirtualProtect")) {
                    hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hVirtualProtect);
                }

                if (!strcmp(pImport->Name, "HeapAlloc")) {
					hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hHeapAlloc);
				}

                if (!strcmp(pImport->Name, "HeapFree")) {
                    hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hHeapFree);
                }

                if (!strcmp(pImport->Name, "LoadLibraryA")) {
					hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hLoadLibraryA);
				}

                if (!strcmp(pImport->Name, "LocalFree")) {
                    hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hLocalFree);
                }

                if (!strcmp(pImport->Name, "VirtualQuery")) {
					hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hVirtualQuery);
				}

                if (!strcmp(pImport->Name, "InternetOpenW")) {
					hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hInternetOpenW);
				}

                if (!strcmp(pImport->Name, "InternetOpenUrlW")) {
                    hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hInternetOpenUrlW);
                }

                if (!strcmp(pImport->Name, "InternetReadFile")) {
                    hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hInternetReadFile);
                }

                if (!strcmp(pImport->Name, "VirtualProtectEx")) {
					hookIatTableEntry((PVOID*)&pFunc->u1.Function, (PVOID)_hVirtualProtectEx);
				}

            }

            pThunk++;
            pFunc++;
        }

        importTbl++;
    }

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        initHooks();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


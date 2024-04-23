#include "pch.h"

#include <Windows.h>
#include <winternl.h>
#include <detours/detours.h>
#include <iostream>
#include <ntstatus.h>
#include <WinUser.h>
#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <wininet.h>
#include <stdint.h>

#pragma comment(lib, "Ntdll.lib")
#pragma comment(lib, "wininet.lib")


template <typename T>
void AttachHook(T& originalFunction, T hookFunction, const char* moduleName, const char* functionName)
{
    originalFunction = reinterpret_cast<T>(DetourFindFunction(moduleName, functionName));
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&originalFunction), hookFunction);
    DetourTransactionCommit();
}

template <typename T>
void DetachHook(T& originalFunction, T hookFunction)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(reinterpret_cast<PVOID*>(&originalFunction), hookFunction);
    DetourTransactionCommit();
}

typedef NTSTATUS(__stdcall* _NtWriteFile)(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID            ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
    );

typedef NTSTATUS(__stdcall* _NtClose)(
    HANDLE Handle
    );

_NtWriteFile NtWriteFile;

UNICODE_STRING pipeName;
HMODULE hNtdll;

std::string lpvoidToString(LPVOID lpAddress) {
    std::stringstream ss;
    ss << std::uppercase << std::hex << reinterpret_cast<uintptr_t>(lpAddress);
    return ss.str();
}


extern "C" {
    typedef NTSTATUS(NTAPI* pNtCreateFile)(
        PHANDLE FileHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        PLARGE_INTEGER AllocationSize,
        ULONG FileAttributes,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        PVOID EaBuffer,
        ULONG EaLength);

    typedef NTSTATUS(NTAPI* pNtWriteFile)(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        PVOID Buffer,
        ULONG Length,
        PLARGE_INTEGER ByteOffset,
        PULONG Key);
}

//void sendMsgThroughBeotmNamedPipe(const char* data, SIZE_T size)
//{
//    HANDLE hPipe;
//    IO_STATUS_BLOCK ioStatusBlock;
//    LARGE_INTEGER allocationSize;
//    ULONG bytesWritten;
//
//    OBJECT_ATTRIBUTES objAttr;
//    UNICODE_STRING pipeName;
//    RtlInitUnicodeString(&pipeName, L"\\Device\\NamedPipe\\beotm_ch3");
//    InitializeObjectAttributes(&objAttr, &pipeName, OBJ_CASE_INSENSITIVE, NULL, NULL);
//
//    pNtCreateFile NtCreateFile = (pNtCreateFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");
//    pNtWriteFile NtWriteFile = (pNtWriteFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtWriteFile");
//
//    NTSTATUS status = NtCreateFile(&hPipe, FILE_WRITE_DATA | SYNCHRONIZE, &objAttr, &ioStatusBlock, &allocationSize, 0, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
//
//    if (!NT_SUCCESS(status)) {
//        std::cerr << "[!] Failed to open named pipe. Error code: " << RtlNtStatusToDosError(status) << std::endl;
//        return;
//    }
//
//    status = NtWriteFile(hPipe, NULL, NULL, NULL, &ioStatusBlock, (PVOID)data, size, NULL, NULL);
//
//    if (!NT_SUCCESS(status)) {
//        std::cerr << "[!] Failed to write to named pipe. Error code: " << RtlNtStatusToDosError(status) << std::endl;
//        NtClose(hPipe);
//        return;
//    }
//
//    NtClose(hPipe);
//}

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


std::string formatToJson(const char* functionName, const void* data, size_t size) {
    std::ostringstream oss;
    oss << "{ ";
    oss << "\"Function\": \"" << functionName << "\", ";
    oss << "\"RawData\": \"";

    const unsigned char* byteData = reinterpret_cast<const unsigned char*>(data);
    for (size_t i = 0; i < size; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byteData[i]);
    }

    oss << "\" }";
    return oss.str();
}

std::string formatToJson_ntf(const char* functionName) {
    std::ostringstream oss;
    oss << "{ ";
    oss << "\"Function\": \"" << functionName << " \" ";
    oss << " }";
    return oss.str();
}

std::string formatToJson_ss(const char* functionName, const char* data) {
    std::ostringstream oss;
    oss << "{ ";
    oss << "\"Function\": \"" << functionName << "\", ";
    oss << "\"StringData\": " << " \" " << data << " \" ";
    oss << "}";
    return oss.str();
}

void PrintBaseAddressAsBytes(PVOID* baseAddress, BYTE* byteArray) {
    BYTE* bytePointer = reinterpret_cast<BYTE*>(*baseAddress);
    size_t sizeOfPVOID = sizeof(PVOID);
    std::memcpy(byteArray, bytePointer, sizeOfPVOID);
}

// HeapAlloc definition
static LPVOID(WINAPI* OriginalHeapAlloc)(
	HANDLE hHeap,
	DWORD  dwFlags,
	SIZE_T dwBytes
	) = HeapAlloc;

__declspec(dllexport) LPVOID _HeapAlloc(
    HANDLE hHeap,
    DWORD  dwFlags,
    SIZE_T dwBytes
) {    
	std::string out = formatToJson_ntf((char*)"HeapAlloc");
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalHeapAlloc(
		hHeap,
		dwFlags,
		dwBytes
	);
}

// HeapFree definition
static BOOL(WINAPI* OriginalHeapFree)(
	HANDLE hHeap,
	DWORD  dwFlags,
	LPVOID lpMem
	) = HeapFree;

__declspec(dllexport) BOOL _HeapFree(
	HANDLE hHeap,
	DWORD  dwFlags,
	LPVOID lpMem
) {
    DetachHook(OriginalHeapFree, _HeapFree);
    
    //printf("HeapFree !!!! \n");
    std::string out = formatToJson_ntf((char*)"HeapFree");
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());
    
    AttachHook(OriginalHeapFree, _HeapFree, "kernelbase.dll", "HeapFree");

    return OriginalHeapFree(
		hHeap,
		dwFlags,
		lpMem
	);
}

// RtlAllocateHeap definition

static LPVOID(WINAPI* OriginalVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
) = VirtualAlloc;

__declspec(dllexport) LPVOID _VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
) {

    std::string out = formatToJson_ss((char*)"VirtualAlloc", lpvoidToString(lpAddress).c_str());
    //printf("%s", out.c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalVirtualAlloc(
        lpAddress,
        dwSize,
        flAllocationType,
        flProtect
        );
}


static LPVOID(WINAPI* OriginalVirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
) = VirtualAllocEx;

__declspec(dllexport) LPVOID _VirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
) {

    std::string out = formatToJson_ss((char*)"VirtualAllocEx", lpvoidToString(lpAddress).c_str());
    //printf("%s", out.c_str());
    sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalVirtualAlloc(
        lpAddress,
        dwSize,
        flAllocationType,
        flProtect
    );
}


typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

WriteProcessMemory_t OriginalWriteProcessMemory = WriteProcessMemory;

__declspec(dllexport) BOOL _WriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T * lpNumberOfBytesWritten
) {

	std::string out = formatToJson_ss((char*)"WriteProcessMemory", lpvoidToString((LPVOID)lpBuffer).c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalWriteProcessMemory(
		hProcess,
		lpBaseAddress,
		lpBuffer,
		nSize,
		lpNumberOfBytesWritten
	);
}

static BOOL(WINAPI* OriginalVirtualProtectEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) = VirtualProtectEx;

__declspec(dllexport) BOOL _VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
) {

	std::string out = formatToJson_ss((char*)"VirtualProtectEx", lpvoidToString(lpAddress).c_str());
	//printf("%s", out.c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalVirtualProtectEx(
		hProcess,
		lpAddress,
		dwSize,
		flNewProtect,
		lpflOldProtect
	);

}

// same with VirtualFree
static BOOL(WINAPI* OriginalVirtualFree)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  dwFreeType
) = VirtualFree;

__declspec(dllexport) BOOL _VirtualFree(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType
) {

	std::string out = formatToJson_ss((char*)"VirtualFree", lpvoidToString(lpAddress).c_str());
	//printf("%s", out.c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalVirtualFree(
		lpAddress,
		dwSize,
		dwFreeType
	);
}

// same with VirtualFreeEx
static BOOL(WINAPI* OriginalVirtualFreeEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  dwFreeType
) = VirtualFreeEx;

__declspec(dllexport) BOOL _VirtualFreeEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType
) {

	std::string out = formatToJson_ss((char*)"VirtualFreeEx", lpvoidToString(lpAddress).c_str());
	//printf("%s", out.c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalVirtualFreeEx(
		hProcess,
		lpAddress,
		dwSize,
		dwFreeType
	);
}

// same with VirtualProtect
static BOOL(WINAPI* OriginalVirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
) = VirtualProtect;

__declspec(dllexport) BOOL _VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
) {

	std::string out = formatToJson_ss((char*)"VirtualProtect", lpvoidToString(lpAddress).c_str());
	//printf("%s", out.c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalVirtualProtect(
		lpAddress,
		dwSize,
		flNewProtect,
		lpflOldProtect
	);
}

// same with MapViewOfFile
static LPVOID(WINAPI* OriginalMapViewOfFile)(
	HANDLE hFileMappingObject,
	DWORD  dwDesiredAccess,
	DWORD  dwFileOffsetHigh,
	DWORD  dwFileOffsetLow,
	SIZE_T dwNumberOfBytesToMap
) = MapViewOfFile;

__declspec(dllexport) LPVOID _MapViewOfFile(
    HANDLE hFileMappingObject,
    DWORD  dwDesiredAccess,
    DWORD  dwFileOffsetHigh,
    DWORD  dwFileOffsetLow,
    SIZE_T dwNumberOfBytesToMap
) {

	std::string out = formatToJson_ss((char*)"MapViewOfFile", lpvoidToString((LPVOID)hFileMappingObject).c_str());
	//printf("%s", out.c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalMapViewOfFile(
		hFileMappingObject,
		dwDesiredAccess,
		dwFileOffsetHigh,
		dwFileOffsetLow,
		dwNumberOfBytesToMap
	);
}

static BOOL(WINAPI* OriginalUnmapViewOfFile)(
	LPCVOID lpBaseAddress
) = UnmapViewOfFile;

__declspec(dllexport) BOOL _UnmapViewOfFile(
    LPCVOID lpBaseAddress
) {

	std::string out = formatToJson_ss((char*)"UnmapViewOfFile", lpvoidToString((LPVOID)lpBaseAddress).c_str());
	//printf("%s", out.c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalUnmapViewOfFile(
		lpBaseAddress
	);
}

static SIZE_T(WINAPI* OriginalVirtualQuery)(
	LPCVOID                   lpAddress,
	PMEMORY_BASIC_INFORMATION  lpBuffer,
	SIZE_T                    dwLength
) = VirtualQuery;

__declspec(dllexport) SIZE_T _VirtualQuery(
    LPCVOID                   lpAddress,
    PMEMORY_BASIC_INFORMATION  lpBuffer,
    SIZE_T                    dwLength
) {

	std::string out = formatToJson_ss((char*)"VirtualQuery", lpvoidToString((LPVOID)lpAddress).c_str());
	//printf("%s", out.c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalVirtualQuery(
		lpAddress,
		lpBuffer,
		dwLength
	);
}

static BOOL(WINAPI* OriginalReadProcessMemory)(
	HANDLE  hProcess,
	LPCVOID lpBaseAddress,
	LPVOID  lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesRead
) = ReadProcessMemory;

__declspec(dllexport) BOOL _ReadProcessMemory(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesRead
) {

	std::string out = formatToJson_ss((char*)"ReadProcessMemory", lpvoidToString((LPVOID)lpBaseAddress).c_str());
	//printf("%s", out.c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalReadProcessMemory(
		hProcess,
		lpBaseAddress,
		lpBuffer,
		nSize,
		lpNumberOfBytesRead
	);
}


// Cuz the internet ain't safe boi

static HINTERNET(WINAPI* OriginalInternetOpenUrlW)(
	HINTERNET hInternet,
	LPCWSTR   lpszUrl,
	LPCWSTR   lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwFlags,
	DWORD_PTR dwContext
) = InternetOpenUrlW;

__declspec(dllexport) HINTERNET _InternetOpenUrlW(
    HINTERNET hInternet,
    LPCWSTR   lpszUrl,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
) {

	std::string out = formatToJson_ss((char*)"InternetOpenUrlW", (char*)lpszUrl);
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalInternetOpenUrlW(
		hInternet,
		lpszUrl,
		lpszHeaders,
		dwHeadersLength,
		dwFlags,
		dwContext
	);
}

static BOOL(WINAPI* OriginalInternetReadFile)(
	HINTERNET hFile,
	LPVOID    lpBuffer,
	DWORD     dwNumberOfBytesToRead,
	LPDWORD   lpdwNumberOfBytesRead
) = InternetReadFile;

__declspec(dllexport) BOOL _InternetReadFile(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
) {

	std::string out = formatToJson_ss((char*)"InternetReadFile", lpvoidToString((LPVOID)lpBuffer).c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalInternetReadFile(
		hFile,
		lpBuffer,
		dwNumberOfBytesToRead,
		lpdwNumberOfBytesRead
	);
}


static BOOL(WINAPI* OriginalInternetReadFileExW)(
	HINTERNET           hFile,
	LPINTERNET_BUFFERSW lpBuffersOut,
	DWORD               dwFlags,
	DWORD_PTR           dwContext
) = InternetReadFileExW;

__declspec(dllexport) BOOL _InternetReadFileExW(
    HINTERNET           hFile,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
) {

	std::string out = formatToJson_ss((char*)"InternetReadFileExW", lpvoidToString((LPVOID)lpBuffersOut).c_str());
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalInternetReadFileExW(
		hFile,
		lpBuffersOut,
		dwFlags,
		dwContext
	);
}

static HINTERNET(WINAPI* OriginalInternetOpenW)(
	LPCWSTR lpszAgent,
	DWORD   dwAccessType,
	LPCWSTR lpszProxy,
	LPCWSTR lpszProxyBypass,
	DWORD   dwFlags
) = InternetOpenW;

__declspec(dllexport) HINTERNET _InternetOpenW(
    LPCWSTR lpszAgent,
    DWORD   dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD   dwFlags
) {

	std::string out = formatToJson_ss((char*)"InternetOpenW", (char*)lpszAgent);
	sendMsgThroughBeotmNamedPipe(out.c_str(), (size_t)out.length());

    return OriginalInternetOpenW(
		lpszAgent,
		dwAccessType,
		lpszProxy,
		lpszProxyBypass,
		dwFlags
	);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call) {
    
        case DLL_PROCESS_ATTACH:
   
            AttachHook(OriginalVirtualAlloc, _VirtualAlloc, "kernelbase.dll", "VirtualAlloc");
            AttachHook(OriginalWriteProcessMemory, _WriteProcessMemory, "kernelbase.dll", "WriteProcessMemory");
            AttachHook(OriginalVirtualFree, _VirtualFree, "kernelbase.dll", "VirtualFree");
            AttachHook(OriginalVirtualFreeEx, _VirtualFreeEx, "kernelbase.dll", "VirtualFreeEx");
            AttachHook(OriginalVirtualProtect, _VirtualProtect, "kernelbase.dll", "VirtualProtect");
            AttachHook(OriginalMapViewOfFile, _MapViewOfFile, "kernelbase.dll", "MapViewOfFile");
            AttachHook(OriginalVirtualProtectEx, _VirtualProtectEx, "kernelbase.dll", "VirtualProtectEx");
            AttachHook(OriginalUnmapViewOfFile, _UnmapViewOfFile, "kernelbase.dll", "UnmapViewOfFile");
            AttachHook(OriginalVirtualQuery, _VirtualQuery, "kernelbase.dll", "VirtualQuery");
            AttachHook(OriginalReadProcessMemory, _ReadProcessMemory, "kernelbase.dll", "ReadProcessMemory");
            AttachHook(OriginalInternetOpenUrlW, _InternetOpenUrlW, "wininet.dll", "InternetOpenUrlW");
            AttachHook(OriginalInternetReadFile, _InternetReadFile, "wininet.dll", "InternetReadFile");
            AttachHook(OriginalInternetReadFileExW, _InternetReadFileExW, "wininet.dll", "InternetReadFileExW");
            AttachHook(OriginalInternetOpenW, _InternetOpenW, "wininet.dll", "InternetOpenW");


            // Those who cause trouble / Ceux qui foutent la merde

            //AttachHook(OriginalVirtualAllocEx, _VirtualAllocEx, "kernelbase.dll", "VirtualAllocEx");  --> Fou la merde sur les injecteurs APC
            //AttachHook(OriginalHeapAlloc, _HeapAlloc, "ntdll.dll", "RtlAllocateHeap"); --> Fou la merde partout
            //AttachHook(OriginalHeapFree, _HeapFree, "ntdll.dll", "RtlFreeHep");   --> Fou la merde partout aussi
            

            break;

        case DLL_THREAD_ATTACH:
    

        case DLL_THREAD_DETACH:
           
            break;

        case DLL_PROCESS_DETACH:

            DetachHook(OriginalVirtualAlloc, _VirtualAlloc);
            DetachHook(OriginalWriteProcessMemory, _WriteProcessMemory);
            DetachHook(OriginalVirtualProtectEx, _VirtualProtectEx);
            DetachHook(OriginalVirtualFree, _VirtualFree);
            DetachHook(OriginalVirtualFreeEx, _VirtualFreeEx);
            DetachHook(OriginalVirtualProtect, _VirtualProtect);
            DetachHook(OriginalMapViewOfFile, _MapViewOfFile);
            DetachHook(OriginalUnmapViewOfFile, _UnmapViewOfFile);
            DetachHook(OriginalVirtualQuery, _VirtualQuery);
            DetachHook(OriginalReadProcessMemory, _ReadProcessMemory);
            DetachHook(OriginalInternetOpenUrlW, _InternetOpenUrlW);
            DetachHook(OriginalInternetReadFile, _InternetReadFile);
            DetachHook(OriginalInternetReadFileExW, _InternetReadFileExW);
            DetachHook(OriginalInternetOpenW, _InternetOpenW);
          
            //DetachHook(OriginalVirtualAllocEx, _VirtualAllocEx);
            //DetachHook(OriginalHeapAlloc, _HeapAlloc);
            //DetachHook(OriginalHeapFree, _HeapFree);
            

            break;
        }

    return TRUE;
}
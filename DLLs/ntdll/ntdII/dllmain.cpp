
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
#include <stdint.h>

void  InitializeHooks();
void  UninitializeHooks();

#pragma comment(lib, "Ntdll.lib")
//#pragma comment(lib, "detours.lib")

template <typename T>
BYTE* getHexDump(const T* data, size_t size) {
    const unsigned char* byteData = reinterpret_cast<const unsigned char*>(data);
    BYTE* hexDump = new BYTE[size];

    for (size_t i = 0; i < size; ++i) {
        hexDump[i] = static_cast<BYTE>(byteData[i]);
    }

    return hexDump;
}

template <typename T>
void releaseHexDump(T* hexDump) {
    delete[] hexDump;
}

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

typedef void* (*pfn_memcpy)(void*, const void*, size_t);

void* WINAPI hooked_memcpy(void* dest, const void* src, size_t count);

typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(WINAPI* NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

typedef NTSTATUS(WINAPI* NtAdjustPrivilegesToken)(
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PULONG ReturnLength
    );

//typedef NTSTATUS(NTAPI* NtWriteVirtualMemory)(
//    HANDLE ProcessHandle,
//    PVOID BaseAddress,
//    PVOID Buffer,
//    ULONG NumberOfBytesToWrite,
//    PULONG NumberOfBytesWritten
//    );

// patch

typedef NTSTATUS(WINAPI* NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );


typedef NTSTATUS(WINAPI* NtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

typedef NTSTATUS(WINAPI* NtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

typedef NTSTATUS(WINAPI* NtCreateThread)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    _PCLIENT_ID_ ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOLEAN CreateSuspended
    );

typedef NTSTATUS(WINAPI* NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE StartAddress,
    LPVOID Parameter,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef NTSTATUS(WINAPI* NtCreateUserProcess)(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PVOID CreateInfo,
    PVOID AttributeList
    );

typedef NTSTATUS(WINAPI* NtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    _PCLIENT_ID_ ClientId
    );

// NtQueueApcThread definition
typedef NTSTATUS(WINAPI* NtQueueApcThread)(
    PVOID ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcRoutineContext,
    PVOID ApcStatusBlock,
    PVOID ApcReserved
    );


// Not hooked, for named pipe communication

typedef NTSTATUS(__stdcall* _NtCreateFile)(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
    );

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

std::string formatToJson_NtWriteVirtualMemory2(const char* functionName, const char* bufferAddress) {
    std::ostringstream oss;
    oss << "{ ";
    oss << "\"Function\": \"" << functionName << "\", ";
    oss << "\"StringData\": \"" << bufferAddress << "\" ";
    oss << "}";
    return oss.str();
}


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

pfn_memcpy original_memcpy = nullptr;

NtAllocateVirtualMemory OriginalNtAllocateVirtualMemory = nullptr;
NtProtectVirtualMemory OriginalNtProtectVirtualMemory = nullptr;
NtAdjustPrivilegesToken OriginalNtAdjustPrivilegesToken = nullptr;
NtFreeVirtualMemory OriginalNtFreeVirtualMemory = nullptr;
NtWriteVirtualMemory OriginalNtWriteVirtualMemory = nullptr;
NtMapViewOfSection OriginalNtMapViewOfSection = nullptr;
NtCreateThread OriginalNtCreateThread = nullptr;
NtCreateThreadEx OriginalNtCreateThreadEx = nullptr;
NtCreateUserProcess OriginalNtCreateUserProcess = nullptr;
NtOpenProcess OriginalNtOpenProcess = nullptr;
NtQueueApcThread OriginalNtQueueApcThread = nullptr;

std::string formatToJson_Ntdll_hexdump(const char* functionName, const void* data, size_t size) {

    std::ostringstream oss_c;
    oss_c << "{ ";
    oss_c << "\"Function\": \"" << functionName << "\", ";
    oss_c << "\"StringData\": \"";

    const unsigned char* byteData = reinterpret_cast<const unsigned char*>(data);
    for (size_t i = 0; i < size; ++i) {
        oss_c << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byteData[i]);
    }

    oss_c << "\" }";

    return oss_c.str();
}

std::string formatToJson_Ntdll(const char* functionName, const void* data, size_t size) {

    std::ostringstream oss_c;
    oss_c << "{ ";
    oss_c << "\"Function\": \"" << functionName << "\", ";
    oss_c << "\"RawData\": \"";

    const unsigned char* byteData = reinterpret_cast<const unsigned char*>(data);
    for (size_t i = 0; i < size; ++i) {
        oss_c << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byteData[i]);
    }

    oss_c << "\" }";
    
    return oss_c.str();
}

std::string formatToJson_Ntdll_ntf(const char* functionName) {
    std::ostringstream oss;
    oss << "{ ";
    oss << "\"Function\": \"" << functionName << "\" ";
    oss << "\" }";
    return oss.str();
}

void PrintBaseAddressAsBytes(PVOID* baseAddress, BYTE* byteArray) {
    BYTE* bytePointer = reinterpret_cast<BYTE*>(*baseAddress);
    size_t sizeOfPVOID = sizeof(PVOID);
    std::memcpy(byteArray, bytePointer, sizeOfPVOID);
}

void printBaseAddressAsBytesWithNoPointer(PVOID baseAddress, BYTE* byteArray) {
	BYTE* bytePointer = reinterpret_cast<BYTE*>(baseAddress);
	size_t sizeOfPVOID = sizeof(PVOID);
	std::memcpy(byteArray, bytePointer, sizeOfPVOID);
}

std::string convertBaseAddressToString(PVOID* baseAddress, SIZE_T size) {
    BYTE* bytePointer = (BYTE*)(*baseAddress);

    std::stringstream stream;

    for (size_t i = 0; i < size; ++i) {
        stream << std::hex << std::setw(2) << std::setfill('0') << (int)(bytePointer[i]);
    }

    return stream.str();
}

std::string formatToJson_NtWrite(const char* functionName, const void* bufferAddress) {
    std::ostringstream oss;
    oss << "{ ";
    oss << "\"Function\": \"" << functionName << "\", ";
    oss << "\"BufferAddress\": \"" << bufferAddress << "\" ";
    oss << "}";
    return oss.str();
}


std::string formatToJson_NtWriteVirtualMemory(const std::string& functionName, const std::string& address) {
    return "{\"Function\": \"" + functionName + "\", \"StringData\": \"" + address + "\"}";
}

/* ------------------------------------------------------------------------------------------- */

void* WINAPI hooked_memcpy(void* dest, const void* src, size_t count) {

    if (dest != nullptr) {
        BYTE byteArray[7]; //x64
        PrintBaseAddressAsBytes((PVOID*)&src, byteArray);
        std::string out = formatToJson_Ntdll((char*)"memcpy", byteArray, sizeof(byteArray));
        sendMsgThroughBeotmNamedPipe(out.c_str(), (SIZE_T)out.length());
    }

    return original_memcpy(dest, src, count);
}

NTSTATUS WINAPI _NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
) {

    DetachHook(OriginalNtAllocateVirtualMemory, _NtAllocateVirtualMemory);

    if (BaseAddress != nullptr) {
        char bufferAddress[32];
        snprintf(bufferAddress, sizeof(bufferAddress), "%p", (PVOID*)BaseAddress);
        std::string tosend = formatToJson_NtWriteVirtualMemory("NtAllocateVirtualMemory", bufferAddress);

        sendMsgThroughBeotmNamedPipe(tosend.c_str(), (SIZE_T)tosend.length());
    }

    AttachHook(OriginalNtAllocateVirtualMemory, _NtAllocateVirtualMemory, "ntdll.dll", "NtAllocateVirtualMemory");

    NTSTATUS status = OriginalNtAllocateVirtualMemory(
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect
    );
    return status;
}


__declspec(dllexport) NTSTATUS  _NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
) {

    if (BaseAddress != nullptr) {
        char bufferAddress[32];
        snprintf(bufferAddress, sizeof(bufferAddress), "%p", (PVOID*)BaseAddress);
        std::string tosend = formatToJson_NtWriteVirtualMemory("NtProtectVirtualMemory", bufferAddress);

        sendMsgThroughBeotmNamedPipe(tosend.c_str(), (SIZE_T)tosend.length());
	}

    NTSTATUS status = OriginalNtProtectVirtualMemory(
        ProcessHandle,
        BaseAddress,
        NumberOfBytesToProtect,
        NewAccessProtection,
        OldAccessProtection
    );

    return status;
}

__declspec(dllexport) NTSTATUS  _NtAdjustPrivilegesToken(
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PULONG ReturnLength
) {

    return OriginalNtAdjustPrivilegesToken(
        TokenHandle,
        DisableAllPrivileges,
        NewState,
        BufferLength,
        PreviousState,
        ReturnLength
    );
}

std::string addressToString(PVOID address) {
    char buffer[20]; // Adjust the size as needed
    sprintf_s(buffer, "%p", address); // Use sprintf_s instead of sprintf
    return std::string(buffer);
}

void addressToByteArray(PVOID address, BYTE* byteArray, size_t size) {
    BYTE* bytePointer = reinterpret_cast<BYTE*>(address);

    for (size_t i = 0; i < size; ++i) {
        byteArray[i] = *(bytePointer + i);
    }
}

std::string formatToJson_ss(const char* functionName, const char* data) {
    std::ostringstream oss;
    oss << "{ ";
    oss << "\"Function\": \"" << functionName << "\", ";
    oss << "\"RawData\": " << " \" " << data << " \" ";
    oss << "}";
    return oss.str();
}


__declspec(dllexport) NTSTATUS _NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
) {

    DetachHook(OriginalNtWriteVirtualMemory, _NtWriteVirtualMemory);

    char bufferAddress[32];
    sprintf_s(bufferAddress, "%p", (PVOID*)((PVOID&)Buffer));
    std::string tosend = formatToJson_NtWriteVirtualMemory2("NtWriteVirtualMemory", bufferAddress);
    sendMsgThroughBeotmNamedPipe(tosend.c_str(), (SIZE_T)tosend.length());

    AttachHook(OriginalNtWriteVirtualMemory, _NtWriteVirtualMemory, "ntdll.dll", "NtWriteVirtualMemory");

    NTSTATUS status = OriginalNtWriteVirtualMemory(
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToWrite,
        NumberOfBytesWritten
    );

    return status;
}

__declspec(dllexport) NTSTATUS _NtReadVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToRead,
	PSIZE_T NumberOfBytesRead
) {

    if (BaseAddress != nullptr) {
        BYTE byteArray[7]; //x64
		PrintBaseAddressAsBytes((PVOID*)&BaseAddress, byteArray);
		std::string out = formatToJson_Ntdll((char*)"NtReadVirtualMemory", byteArray, sizeof(byteArray));
		sendMsgThroughBeotmNamedPipe(out.c_str(), (SIZE_T)out.length());
    }

	return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS _NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
) {

    if (BaseAddress != nullptr && *BaseAddress != nullptr) {
        BYTE byteArray[7]; //x64
        PrintBaseAddressAsBytes((PVOID*)&BaseAddress, byteArray);
        std::string out = formatToJson_Ntdll((char*)"NtFreeVirtualMemory", byteArray, sizeof(byteArray));
        sendMsgThroughBeotmNamedPipe(out.c_str(), (SIZE_T)out.length());
    }

    NTSTATUS status = OriginalNtFreeVirtualMemory(
		ProcessHandle,
		BaseAddress,
		RegionSize,
		FreeType
	);

    return status;
}


__declspec(dllexport) NTSTATUS  _NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
) {

    NTSTATUS status = OriginalNtMapViewOfSection(
		SectionHandle,
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		CommitSize,
		SectionOffset,
		ViewSize,
		InheritDisposition,
		AllocationType,
		Win32Protect
	);

    if (BaseAddress != nullptr && *BaseAddress != nullptr) {
        BYTE byteArray[7]; //x64
        PrintBaseAddressAsBytes((PVOID*)&BaseAddress, byteArray);
        std::string out = formatToJson_Ntdll((char*)"NtMapViewOfSection", byteArray, sizeof(byteArray));
        sendMsgThroughBeotmNamedPipe(out.c_str(), (SIZE_T)out.length());
    }

    return status;
}


__declspec(dllexport) NTSTATUS  _NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE StartAddress,
    LPVOID Parameter,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
) {
        

    return OriginalNtCreateThreadEx(
        ThreadHandle,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        StartAddress,
        Parameter,
        CreateFlags,
        ZeroBits,
        StackSize,
        MaximumStackSize,
        AttributeList
    );
}

__declspec(dllexport) NTSTATUS  _NtCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PVOID CreateInfo,
    PVOID AttributeList
) {

    return OriginalNtCreateUserProcess(
		ProcessHandle,
		ThreadHandle,
		ProcessDesiredAccess,
		ThreadDesiredAccess,
		ProcessObjectAttributes,
		ThreadObjectAttributes,
		ProcessFlags,
		ThreadFlags,
		ProcessParameters,
		CreateInfo,
		AttributeList
	);
}

__declspec(dllexport) NTSTATUS  _NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    _PCLIENT_ID_ ClientId
) {

    return OriginalNtOpenProcess(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId
	);
}

__declspec(dllexport) NTSTATUS _NtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcRoutineContext,
    PVOID ApcStatusBlock,
    PVOID ApcReserved
) {

    char bufferAddress[32]; // Ajustez la taille en fonction de vos besoins
    sprintf_s(bufferAddress, "%p", (PVOID*)((PVOID)ApcRoutine));
    std::string tosend = formatToJson_NtWriteVirtualMemory("NtQueueApcThread", bufferAddress);
    sendMsgThroughBeotmNamedPipe(tosend.c_str(), (SIZE_T)tosend.length());


    return OriginalNtQueueApcThread(
		ThreadHandle,
		ApcRoutine,
		ApcRoutineContext,
		ApcStatusBlock,
		ApcReserved
	);
}

void InitializeHooks()
{

    AttachHook(OriginalNtProtectVirtualMemory, _NtProtectVirtualMemory, "ntdll.dll", "NtProtectVirtualMemory");
    AttachHook(OriginalNtWriteVirtualMemory, _NtWriteVirtualMemory, "ntdll.dll", "NtWriteVirtualMemory");
    AttachHook(OriginalNtMapViewOfSection, _NtMapViewOfSection, "ntdll.dll", "NtMapViewOfSection");
 
}

void UninitializeHooks()
{
    DetachHook(OriginalNtAdjustPrivilegesToken, _NtAdjustPrivilegesToken);
    DetachHook(OriginalNtWriteVirtualMemory, _NtWriteVirtualMemory);
    DetachHook(OriginalNtMapViewOfSection, _NtMapViewOfSection);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        InitializeHooks();
        break;
    
    case DLL_PROCESS_DETACH:
        
        FreeLibrary(hNtdll);
        UninitializeHooks();
        break;
    
    }
    return TRUE;
}

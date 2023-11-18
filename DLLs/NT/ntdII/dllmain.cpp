#include "pch.h"
#include <Windows.h>
#include <detours/detours.h>
#include <iostream>
#include <ntstatus.h>
#include <WinUser.h>

void interceptMsg(char* rName) {
    std::cout << "Intercepted " << rName << std::endl;
}

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


NtAllocateVirtualMemory OriginalNtAllocateVirtualMemory = nullptr;
NtProtectVirtualMemory OriginalNtProtectVirtualMemory = nullptr;
NtAdjustPrivilegesToken OriginalNtAdjustPrivilegesToken = nullptr;
NtWriteVirtualMemory OriginalNtWriteVirtualMemory = nullptr;
NtFreeVirtualMemory OriginalNtFreeVirtualMemory = nullptr;
NtMapViewOfSection OriginalNtMapViewOfSection = nullptr;
NtCreateThread OriginalNtCreateThread = nullptr;
NtCreateThreadEx OriginalNtCreateThreadEx = nullptr;
NtCreateUserProcess OriginalNtCreateUserProcess = nullptr;
NtOpenProcess OriginalNtOpenProcess = nullptr;

NTSTATUS WINAPI _NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
) 
{

    interceptMsg((char*)"NtAllocateVirtualMemory");

    return OriginalNtAllocateVirtualMemory(
        ProcessHandle, 
        BaseAddress,
        ZeroBits, 
        RegionSize, 
        AllocationType, 
        Protect
    );
}

__declspec(dllexport) NTSTATUS  _NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
) {

    interceptMsg((char*)"NtProtectVirtualMemory");

    return OriginalNtProtectVirtualMemory(
        ProcessHandle,
        BaseAddress,
        NumberOfBytesToProtect,
        NewAccessProtection,
        OldAccessProtection
    );
}

__declspec(dllexport) NTSTATUS  _NtAdjustPrivilegesToken(
    HANDLE TokenHandle,
    BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState,
    ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState,
    PULONG ReturnLength
) {

    interceptMsg((char*)"NtAdjustPrivilegesToken");

    return OriginalNtAdjustPrivilegesToken(
        TokenHandle,
        DisableAllPrivileges,
        NewState,
        BufferLength,
        PreviousState,
        ReturnLength
    );
}

__declspec(dllexport) NTSTATUS  _NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
) {

    interceptMsg((char*)"NtWriteVirtualMemory");

    return OriginalNtWriteVirtualMemory(
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToWrite,
        NumberOfBytesWritten
    );
}

__declspec(dllexport) NTSTATUS  _NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
) {

    interceptMsg((char*)"NtFreeVirtualMemory");

    return OriginalNtFreeVirtualMemory(
        ProcessHandle,
        BaseAddress,
        RegionSize,
        FreeType
    );
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

    interceptMsg((char*)"NtMapViewOfSection");

    return OriginalNtMapViewOfSection(
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
}

/*
__declspec(dllexport) NTSTATUS  _NtCreateThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    _PCLIENT_ID_ ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOLEAN CreateSuspended
) {

    interceptMsg((char*)"NtCreateThread");

    return OriginalNtCreateThread(
        ThreadHandle,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        ClientId,
        ThreadContext,
        InitialTeb,
        CreateSuspended
    );
}
*/

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

    interceptMsg((char*)"NtCreateThreadEx");

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

/*
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

    interceptMsg((char*)"NtCreateUserProcess");

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
*/

/*
__declspec(dllexport) NTSTATUS  _NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    _PCLIENT_ID_ ClientId
) {

    interceptMsg((char*)"NtopenProcess");

    return OriginalNtOpenProcess(
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ClientId
    );
}
*/

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

void InitializeHooks()
{
    AttachHook(OriginalNtAllocateVirtualMemory, _NtAllocateVirtualMemory, "ntdll.dll", "NtAllocateVirtualMemory");
    AttachHook(OriginalNtProtectVirtualMemory, _NtProtectVirtualMemory, "ntdll.dll", "NtProtectVirtualMemory");
    AttachHook(OriginalNtAdjustPrivilegesToken, _NtAdjustPrivilegesToken, "ntdll.dll", "NtAdjustPrivilegesToken");
    AttachHook(OriginalNtWriteVirtualMemory, _NtWriteVirtualMemory, "ntdll.dll", "NtWriteVirtualMemory");
    AttachHook(OriginalNtFreeVirtualMemory, _NtFreeVirtualMemory, "ntdll.dll", "NtFreeVirtualMemory");
    AttachHook(OriginalNtMapViewOfSection, _NtMapViewOfSection, "ntdll.dll", "NtMapViewOfSection");
    
    /*
    AttachHook(OriginalNtCreateThread, _NtCreateThread, "ntdll.dll", "NtCreateThread");
    */
    
    AttachHook(OriginalNtCreateThreadEx, _NtCreateThreadEx, "ntdll.dll", "NtCreateThreadEx");
    
    /*
    AttachHook(OriginalNtCreateUserProcess, _NtCreateUserProcess, "ntdll.dll", "NtCreateUserProcess");
    AttachHook(OriginalNtOpenProcess, _NtOpenProcess, "ntdll.dll", "NtOpenProcess");
    */
}

void UninitializeHooks()
{
    DetachHook(OriginalNtAllocateVirtualMemory, _NtAllocateVirtualMemory);
    DetachHook(OriginalNtProtectVirtualMemory, _NtProtectVirtualMemory);
    DetachHook(OriginalNtAdjustPrivilegesToken, _NtAdjustPrivilegesToken);
    DetachHook(OriginalNtWriteVirtualMemory, _NtWriteVirtualMemory);
    DetachHook(OriginalNtFreeVirtualMemory, _NtFreeVirtualMemory);
    DetachHook(OriginalNtMapViewOfSection, _NtMapViewOfSection);
   
    /*
    DetachHook(OriginalNtCreateThread, _NtCreateThread);
    */
    
    DetachHook(OriginalNtCreateThreadEx, _NtCreateThreadEx);    
    /*
    DetachHook(OriginalNtCreateUserProcess, _NtCreateUserProcess);
    DetachHook(OriginalNtOpenProcess, _NtOpenProcess);
    */
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InitializeHooks();
        break;
    case DLL_PROCESS_DETACH:
        UninitializeHooks();
        break;
    }
    return TRUE;
}

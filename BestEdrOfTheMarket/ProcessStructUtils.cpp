#include "ProcessStructUtils.h"

typedef NTSTATUS(*_NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

_NtQueryInformationProcess NtQueryInformationProcess2 = nullptr;

PPEB getHandledProcessPeb(HANDLE hProcess) {

    HMODULE ntdll = LoadLibrary(L"ntdll.dll");
    NtQueryInformationProcess2 = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");

    PPEB peb = nullptr;
    PROCESS_BASIC_INFORMATION pbi;

    NTSTATUS ret = NtQueryInformationProcess2(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0);
    if (NT_SUCCESS(ret)) {
        peb = pbi.PebBaseAddress;
    }
    return peb;
}

bool IsThreadSuspended(HANDLE hThread) {
    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(hThread, &context)) {
        return (context.ContextFlags & CONTEXT_DEBUG_REGISTERS) != 0;
    }

    return false;
}
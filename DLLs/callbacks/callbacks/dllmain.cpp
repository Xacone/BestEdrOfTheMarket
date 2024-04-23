
//*********************************************************************************//
//
// Strongly inspired from https://github.com/1401199262/InstrumentationCallback (@1401199262)
//  
//*********************************************************************************//


#include "pch.h"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <TlHelp32.h>

typedef NTSTATUS(WINAPI* PFunNtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
    );

HMODULE ntdllModule;
OBJECT_ATTRIBUTES objAttr;
HANDLE hProcess;
PCLIENT_ID_ cID;

#define RIP_SANITY_CHECK(Rip,BaseAddress,ModuleSize) (Rip > BaseAddress) && (Rip < (BaseAddress + ModuleSize))

bool flag = false;

DWORD64 previousRip;

int i = 0;

CONTEXT originalContext;

u32 tls_index = 0;

bool InitSymbol()
{
    SymSetOptions(SYMOPT_UNDNAME);
    if (!SymInitialize((HANDLE)-1, 0, true))
    {
        printf("SymInitialize Failed with %d\n", GetLastError());
        return false;
    }

    return true;
}

PThreadData GetThreadDataBuffer()
{
    pv thread_data = TlsGetValue(tls_index);
    if (!thread_data)
    {
        thread_data = LocalAlloc(LPTR, sizeof(ThreadData));
        if (!thread_data)
            __debugbreak();

        memset(thread_data, 0, sizeof(ThreadData));

        if (!TlsSetValue(tls_index, thread_data))
            __debugbreak();

    }

    return (PThreadData)thread_data;
}

bool InitInstrumentCallback()
{
    tls_index = TlsAlloc();

    if (tls_index == TLS_OUT_OF_INDEXES)
    {
        printf("Couldn't allocate a TLS index\n");
        return false;
    }


    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info;
    info.Version = 0;
    info.Reserved = 0;
    info.Callback = InstrCallbackEntry;

    //NtSetInformationProcess + ProcessInstrumentationCallback 
    auto status = NtSetInformationProcess((HANDLE)-1, 0x28, &info, sizeof(info));
    if (status)
    {
        printf("NtSetInformationProcess Falied with ntstatus %x\n", status);
        return false;
    }

    return true;
}


PFunNtSetInformationProcess ntSetInformationProcess;
PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana;
PROCESS_INFORMATION_CLASS processInfoClass;
NTSTATUS status;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        if (!InitSymbol())
        {
            printf("InitSymbol Failed\n");
            return 0;
        }

        if (!InitInstrumentCallback())
        {
            printf("InitInstrumentCallback Failed\n");
            return 0;
        }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


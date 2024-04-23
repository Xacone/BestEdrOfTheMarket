
//*********************************************************************************//
//
// Strongly inspired from https://github.com/1401199262/InstrumentationCallback (@1401199262)
//  
//*********************************************************************************//


#ifndef PCH_H
#define PCH_H

#include <iostream>
#include <map>
#include <Windows.h>
#include <winternl.h>
#include <DbgHelp.h>

#include "framework.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "imagehlp.lib")

#define noinl __declspec(noinline)
#define naked __declspec(naked)
#define inl __forceinline

using u64 = unsigned long long;
using u32 = unsigned long;
using u16 = unsigned short;
using u8 = unsigned char;
using pv64 = void*;
using pv = void*;
using i64 = __int64;
using u64 = unsigned __int64;
using DWORD = unsigned long;
using WORD = unsigned short;
using BYTE = unsigned char;
using size_t = SIZE_T;
using UINT = unsigned int;

#define PROCESS_INFO_CLASS_INSTRUMENTATION 40

typedef struct _CLIENT_ID_ {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_, * PCLIENT_ID_;


typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;


extern "C" void InstrCallbackEntry();

extern"C" NTSTATUS NTAPI NtSetInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

extern "C" NTSTATUS NtContinue(PCONTEXT, u64);

std::string GetFunctionInfoByAddress(u64 address, u64* FunctionOffset)
{
    auto buffer = malloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    if (!buffer)
        __debugbreak();

    memset(buffer, 0, sizeof(SYMBOL_INFO) + MAX_SYM_NAME);

    auto symbol_information = (PSYMBOL_INFO)buffer;
    symbol_information->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol_information->MaxNameLen = MAX_SYM_NAME;

    auto result = SymFromAddr((HANDLE)-1, address, FunctionOffset, symbol_information);

    if (!result) {
        free(buffer);
        return "Could_Not_Obtain_Name";
    }

    auto built_string = std::string(symbol_information->Name);

    free(buffer);

    return built_string;
}


typedef struct _ThreadData
{
    volatile u8 IsThreadHandlingSyscall;
}ThreadData, * PThreadData;

PThreadData GetThreadDataBuffer();
bool InitInstrumentCallback();

extern "C" void CallbackRoutine(CONTEXT * ctx)
{
    ctx->Rip = __readgsqword(0x02d8);
    ctx->Rsp = __readgsqword(0x02e0);
    ctx->Rcx = ctx->R10;

    PThreadData CurrentThreadData = GetThreadDataBuffer();
    
    if (CurrentThreadData->IsThreadHandlingSyscall)
        NtContinue(ctx, 0);

    CurrentThreadData->IsThreadHandlingSyscall = true;

    u64 SyscallFunctionOffset = 0;
    auto SyscallFunctionName = GetFunctionInfoByAddress(ctx->Rip, &SyscallFunctionOffset);
    printf("syscall function detected : 0x%llx %s+0x%llx\n", ctx->Rip, SyscallFunctionName.c_str(), SyscallFunctionOffset);

    CurrentThreadData->IsThreadHandlingSyscall = false;

    NtContinue(ctx, 0);

    __debugbreak();
}

#endif //PCH_H


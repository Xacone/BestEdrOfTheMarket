#include "pch.h"

#include <Windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <vector>

#include <iostream>

#include "IPCUtils.h"

#pragma comment(lib, "Dbghelp.lib")

PVOID targetAdddr = nullptr;

CONTEXT threadCtx;

HMODULE ntdll = GetModuleHandleA("ntdll");

HANDLE hExHandler;

PVOID NtAlloc = (PVOID)GetProcAddress(ntdll, "NtAllocateVirtualMemory"); // not used

PVOID NtWrite = (PVOID)GetProcAddress(ntdll, "NtWriteVirtualMemory");

PVOID NtProtect = (PVOID)GetProcAddress(ntdll, "NtProtectVirtualMemory");

PVOID NtCreateThrd = (PVOID)GetProcAddress(ntdll, "NtCreateThreadEx");

PVOID NtCreateProc = (PVOID)GetProcAddress(ntdll, "NtCreateUserProcess");


void enable4breakpoints(CONTEXT* ctx, ULONG_PTR addr1, ULONG_PTR addr2, ULONG_PTR addr3, ULONG_PTR addr4) {

    ctx->Dr0 = (ULONG_PTR)addr1;
    ctx->Dr1 = (ULONG_PTR)addr2;
    ctx->Dr2 = (ULONG_PTR)addr3;
    ctx->Dr3 = (ULONG_PTR)addr4;

    ctx->Dr7 |= (1 << 0);
    ctx->Dr7 |= (1 << 2);
    ctx->Dr7 |= (1 << 4);
    ctx->Dr7 |= (1 << 6);
}


void disableBreakpoints(CONTEXT* ctx) {

    ctx->Dr0 = 0;
    ctx->Dr1 = 0;
    ctx->Dr2 = 0;
    ctx->Dr3 = 0;

    ctx->Dr7 = 0;
}

LONG WINAPI exceptionHandler(PEXCEPTION_POINTERS exceptions) {


    PVOID addr = exceptions->ExceptionRecord->ExceptionAddress;

    if (exceptions->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP
        && (addr == (PVOID)((DWORD_PTR)NtWrite + 0x14)) || 
        (addr == (PVOID)((DWORD_PTR)NtProtect + 0x14)) || 
        (addr == (PVOID)((DWORD_PTR)NtCreateThrd + 0x14)) || 
        (addr == (PVOID)((DWORD_PTR)NtCreateProc + 0x14))) 
    
    {
        std::string rspOut = formatRspToJson((*(PVOID*)exceptions->ContextRecord->Rsp));
        sendMsgThroughBeotmNamedPipe(rspOut.c_str(), rspOut.length(), (LPWSTR)L"\\\\.\\pipe\\beotm_ch1");

        CONTEXT* ctx = exceptions->ContextRecord;
        disableBreakpoints(ctx);
        SetThreadContext(GetCurrentThread(), ctx);

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else {
        return EXCEPTION_CONTINUE_SEARCH;
    }
}


DWORD pid;
HANDLE hProcess;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    HANDLE hSnap;
    std::vector<HANDLE> thHandles;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: // Old threads

        //https ://devblogs.microsoft.com/oldnewthing/20060223-14/?p=32173
        
        hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te;
            te.dwSize = sizeof(te);
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                        sizeof(te.th32OwnerProcessID) && (te.th32OwnerProcessID == GetProcessId(GetCurrentProcess()))) {
                            HANDLE thHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                            thHandles.push_back(thHandle);
                    }
                    te.dwSize = sizeof(te);
                } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }

        for (auto thHandle : thHandles) {
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_ALL;

            hExHandler = AddVectoredExceptionHandler(1, exceptionHandler);

            if (GetThreadContext(thHandle, &ctx)) {

                if (NtProtect != nullptr) {
                    
                    enable4breakpoints(&ctx, 
                        (ULONG_PTR)((ULONG_PTR)NtProtect+0x14), 
                        (ULONG_PTR)((ULONG_PTR)NtCreateThrd + 0x14), 
                        (ULONG_PTR)((ULONG_PTR)NtWrite + 0x14),
                        (ULONG_PTR)((ULONG_PTR)NtCreateProc + 0x14)
                    );
                    
                    SetThreadContext(thHandle, &ctx);
                }
            }
        }


    case DLL_THREAD_ATTACH: // New threads
        
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_ALL;
        hExHandler = AddVectoredExceptionHandler(1, exceptionHandler);
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            
            enable4breakpoints(&ctx, 
                (ULONG_PTR)((ULONG_PTR)NtProtect+0x14), 
                (ULONG_PTR)((ULONG_PTR)NtCreateThrd + 0x14), 
                (ULONG_PTR)((ULONG_PTR)NtWrite + 0x14),
                (ULONG_PTR)((ULONG_PTR)NtCreateProc + 0x14)
            );
            
            
            SetThreadContext(GetCurrentThread(), &ctx);
        }

    case DLL_THREAD_DETACH:

        GetThreadContext(GetCurrentThread(), &ctx);
        disableBreakpoints(&ctx);

    case DLL_PROCESS_DETACH:
        
        break;
    }
    return TRUE;
}


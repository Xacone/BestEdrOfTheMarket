#include "pch.h"

#include <Windows.h>
#include <detours/detours.h>
#include <iostream>

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

    MessageBoxA(NULL, "VirtualAlloc Intercepted", "Intercepted", MB_ICONINFORMATION);

    return OriginalVirtualAlloc(
        lpAddress,
        dwSize,
        flAllocationType,
        flProtect
        );
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalVirtualAlloc, _VirtualAlloc);
        DetourTransactionCommit();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread);
        DetourDetach(&(PVOID&)OriginalVirtualAlloc, _VirtualAlloc);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}

#pragma once

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

#include "ConversionUtils.h"

class DllLoader {

private:

    HANDLE hProc = NULL;
    char fullDllName[MAX_PATH] = {};
    LPVOID loadLibrary = NULL;
    LPVOID allocatedPoolStartAddr = NULL;

public:
    
    DllLoader(HANDLE hProc) {
        this->hProc = hProc;
    }    

    //Might not work with loading-protected / dll-hijacking-protected processes   
    BOOL InjectDll(DWORD procID, char* dllName, LPVOID& poolStart) {
       
        char fullDllName[MAX_PATH];
        LPVOID loadLibrary;
        LPVOID remoteString;

        if (procID == 0) {
            return FALSE;
            return FALSE;
        }

        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
        if (hProc == INVALID_HANDLE_VALUE) {
            return FALSE;
        }

        GetFullPathNameA(dllName, MAX_PATH, fullDllName, NULL);

        loadLibrary = (LPVOID)GetProcAddress(GetModuleHandle(ConvertCharToLPCWSTR("kernel32.dll")), "LoadLibraryA");

        remoteString = VirtualAllocEx(hProc, NULL, strlen(fullDllName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            
        WriteProcessMemory(hProc, remoteString, fullDllName, strlen(fullDllName), NULL);
   
        CreateRemoteThread(hProc, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibrary, (LPVOID)remoteString, NULL, NULL);
        
        CloseHandle(hProc);

        return TRUE;
    }
};
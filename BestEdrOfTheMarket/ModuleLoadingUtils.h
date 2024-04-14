/**
* @file ModuleLoadingUtils.h
* @brief Module injection utility class
*/

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
    
    /**
    * @brief Constructor for the DllLoader class
    * @param hProc Handle to the process to inject the DLL into
    */

    DllLoader(HANDLE hProc) {
        this->hProc = hProc;
    }    

    /**
    * Injects a DLL into a target process
    * @param dllName Name of the DLL to inject
    * @return TRUE if the DLL was successfully injected, FALSE otherwise
    */
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
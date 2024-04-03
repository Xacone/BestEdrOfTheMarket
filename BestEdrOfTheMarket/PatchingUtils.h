#pragma once

#include <Windows.h>
#include <string>

#pragma comment(lib, "ntdll.lib")

#include "ConversionUtils.h"

class PatchingMitigationUtils {

    // AmsiOpenSession
    // AMsiScanBuffer
    // EtwEventWrite
    // NtTraceEvents

private:

    HANDLE target;

    BYTE AmsiOpenSessionOpCodes[100];
    BYTE AmsiScanBufferOpCodes[100];
    BYTE EtwEventWriteOpCodes[100];
    BYTE NtTraceEventsOpCodes[100];
	
public:

    int checkRemoteFunction(PVOID remoteFunctionAddr, const BYTE* expectedOpCodes, size_t opCodeSize) {
        BYTE* buffer = new BYTE[opCodeSize];
        SIZE_T bytesRead;

        if (!ReadProcessMemory(target, remoteFunctionAddr, buffer, opCodeSize, &bytesRead)) {
            delete[] buffer;
            return FALSE;
        }

        int result = (memcmp(buffer, expectedOpCodes, opCodeSize) == 0);

        delete[] buffer;
        return result;
    }

    PatchingMitigationUtils(HANDLE target) {
    
        this->target = target;

        memcpy(AmsiOpenSessionOpCodes, (PVOID)AmsiOpenSession, sizeof(AmsiOpenSessionOpCodes));
        memcpy(AmsiScanBufferOpCodes, (PVOID)AmsiScanBuffer, sizeof(AmsiScanBufferOpCodes));
   /*     memcpy(EtwEventWriteOpCodes, (PVOID)GetProcAddress(GetModuleHandleA("ntdll"), "EtwEventWrite"), sizeof(EtwEventWriteOpCodes));
        memcpy(NtTraceEventsOpCodes, (PVOID)GetProcAddress(GetModuleHandleA("ntdll"), "NtTraceEvent"), sizeof(NtTraceEventsOpCodes));*/
    
    }

    BOOL checkAmsiScanBuffer(PVOID AmsiScanBufferAddr) {
        return checkRemoteFunction(AmsiScanBufferAddr, AmsiScanBufferOpCodes, sizeof(AmsiScanBufferOpCodes));
    }

    BOOL checkAmsiOpenSession(PVOID AmsiOpenSessionAddr) {
        return checkRemoteFunction(AmsiOpenSessionAddr, AmsiOpenSessionOpCodes, sizeof(AmsiOpenSessionOpCodes));
    }

    BOOL checkEtwEventWrite(PVOID EtwEventWriteAddr) {
        return checkRemoteFunction(EtwEventWriteAddr, EtwEventWriteOpCodes, sizeof(EtwEventWriteOpCodes));
    }

    BOOL checkNtTraceEvents(PVOID NtTraceEventAddr) {
        return checkRemoteFunction(NtTraceEventAddr, NtTraceEventsOpCodes, sizeof(NtTraceEventsOpCodes));
    }
};
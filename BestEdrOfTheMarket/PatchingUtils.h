/**
* @file PatchingUtils.h
* @brief Contains utilities for AMSI/ETW patching detection
*/


#pragma once

#include <Windows.h>
#include <string>

#pragma comment(lib, "ntdll.lib")

#include "ConversionUtils.h"

class PatchingMitigationUtils {


private:

    HANDLE target;

    PVOID AmsiOpenSessionAddr;
    PVOID AmsiScanBufferAddr;
    PVOID EtwEventWriteAddr;
    PVOID NtTraceEventsAddr;

    BYTE AmsiOpenSessionOpCodes_init[100];
    BYTE AmsiScanBufferOpCodes_init[100];
    BYTE EtwEventWriteOpCodes_init[100];
    BYTE NtTraceEventsOpCodes_init[100];

    BYTE AmsiOpenSessionOpCodes[100];
    BYTE AmsiScanBufferOpCodes[100];
    BYTE EtwEventWriteOpCodes[100];
    BYTE NtTraceEventsOpCodes[100];

    BOOL init = false;

public:

    /**
    * @brief Check if the remote process has been patched
    * @param amsiEnabled If AMSI is enabled
    * @return TRUE if the remote process has been patched, FALSE otherwise
    * @note This function checks if the remote process has been patched by comparing the current opcodes of the functions with the initial opcodes
    */

    BOOL checkRemoteFunction(BOOL amsiEnabled) {

        if (amsiEnabled) {

            if (ReadProcessMemory(target, (PVOID)AmsiOpenSessionAddr, AmsiOpenSessionOpCodes, sizeof(AmsiOpenSessionOpCodes), NULL)) {
                if (!init) {
                    memcpy(AmsiOpenSessionOpCodes_init, AmsiOpenSessionOpCodes, sizeof(AmsiOpenSessionOpCodes));
                    //init = true;
                }
                else {
                    if (memcmp(AmsiOpenSessionOpCodes, AmsiOpenSessionOpCodes_init, sizeof(AmsiOpenSessionOpCodes))) {
                        return FALSE;
                    }
                }
            }

            if (ReadProcessMemory(target, (PVOID)AmsiScanBufferAddr, AmsiScanBufferOpCodes, sizeof(AmsiScanBufferOpCodes), NULL)) {
                if (!init) {
                    memcpy(AmsiScanBufferOpCodes_init, AmsiScanBufferOpCodes, sizeof(AmsiScanBufferOpCodes));
                }
                else {
                    if (memcmp(AmsiScanBufferOpCodes, AmsiScanBufferOpCodes_init, sizeof(AmsiScanBufferOpCodes))) {
                        return FALSE;
                    }

                }
            }
        }


        if (ReadProcessMemory(target, (PVOID)EtwEventWriteAddr, EtwEventWriteOpCodes, sizeof(EtwEventWriteOpCodes), NULL)) {
            if (!init) {
                memcpy(EtwEventWriteOpCodes_init, EtwEventWriteOpCodes, sizeof(EtwEventWriteOpCodes));
            }
            else {
                if (memcmp(EtwEventWriteOpCodes, EtwEventWriteOpCodes_init, sizeof(EtwEventWriteOpCodes))) {
                    return FALSE;
                }
            }
        }

        if (ReadProcessMemory(target, (PVOID)NtTraceEventsAddr, NtTraceEventsOpCodes, sizeof(NtTraceEventsOpCodes), NULL)) {
                
            if (!init) {
                memcpy(NtTraceEventsOpCodes_init, NtTraceEventsOpCodes, sizeof(NtTraceEventsOpCodes));
                init = TRUE;
            }
            else {
                if (memcmp(NtTraceEventsOpCodes, NtTraceEventsOpCodes_init, sizeof(NtTraceEventsOpCodes))) {
                    return FALSE;
                }
            }
        }
        

        return TRUE;

    }

    /** 
        * Retrieves the addresses of targeted functions from the remote process
        * @param AmsiOpenSession_ Remote address of AmsiOpenSession
        * @param AmsiScanBuffer_ Remote address of AmsiScanBuffer
        * @param EtwEventWrite_ Remote address of EtwEventWrite
        * @param NtTraceEvents_ Remote address of NtTraceEvents
    */

    void fillProtectedFunctions(
        PVOID AmsiOpenSession_,
        PVOID AmsiScanBuffer_,
        PVOID EtwEventWrite_,
        PVOID NtTraceEvents_
    ) {

        AmsiOpenSessionAddr = AmsiOpenSession_;
        AmsiScanBufferAddr = AmsiScanBuffer_;
        EtwEventWriteAddr = EtwEventWrite_;
        NtTraceEventsAddr = NtTraceEvents_;
    }

    /**
    * @brief Constructor for PatchingMitigationUtils
    * @param target The handle to the remote process
    */
    PatchingMitigationUtils(HANDLE target) {
        this->target = target;
    }

};

#include "Globals.h"

VOID SsdtUtils::InitExportsMap() {
	InitializeFunctionMap(&exportsMap);
}

ULONGLONG SsdtUtils::LeakKeServiceDescriptorTableVPT() {

	ULONG64 kiSystemCall64 = (ULONG64)__readmsr(MSR_IA32_LSTAR);

    for (int i = 0; i < 0x1000; i++) {

        __try {
            UINT8 sig_bytes[] = { 0x4C, 0x8D, 0x15 };

            ULONGLONG val = *(PULONGLONG)kiSystemCall64;

            if (contains_signature((ULONGLONG)&val, 8, sig_bytes, sizeof(sig_bytes))) {

                ULONG64 offset = ((*(PULONG64)(kiSystemCall64 + 4) >> 24) & 0x00FFFFFFFF);

				ULONGLONG keServiceDescriptorTable = kiSystemCall64 + 8 + 4 - 1 + offset;

                return keServiceDescriptorTable;
            }

            kiSystemCall64 += 2;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] Exception\n");
            return NULL;
        }
    }

    return NULL;
}

ULONGLONG SsdtUtils::LeakKiSystemServiceUser() {

    QWORD KiSystemCall64Shadow = (QWORD)__readmsr(MSR_IA32_LSTAR);
    ULONGLONG lastJmpAddr = NULL;

    do {
        __try {

            KiSystemCall64Shadow += 2;
            UINT8 jmp_byte[] = { 0xE9 };

            if (contains_bytes_bitwise(*(PULONG)KiSystemCall64Shadow, jmp_byte, 1)) {
                lastJmpAddr = KiSystemCall64Shadow;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] Exception\n");
            return NULL;
        }

    } while (*(PULONG)KiSystemCall64Shadow != 0);

    LONG kiSystemServiceUserOffset = -(*(PLONG)(lastJmpAddr + 2));
    ULONGLONG kiSystemServiceUser = (ULONGLONG)((lastJmpAddr + 2 + 4) - (LONG)kiSystemServiceUserOffset);

    return kiSystemServiceUser;
}

ULONGLONG SsdtUtils::LeakKeServiceDescriptorTable(ULONGLONG kiSystemUser) {

    for (int i = 0; i < 0x1000; i++) {

        __try {
            UINT8 sig_bytes[] = { 0x4C, 0x8D, 0x15 };

            ULONGLONG val = *(PULONGLONG)kiSystemUser;

            if (contains_signature((ULONGLONG)&val, 8, sig_bytes, sizeof(sig_bytes))) {

                ULONG kiSystemServiceRepeatOffset = (*(PLONG)(kiSystemUser + 8));

				ULONGLONG keServiceDescriptorTable = kiSystemUser + 8 + 4 + kiSystemServiceRepeatOffset;
               
                return keServiceDescriptorTable;
            }

            kiSystemUser += 2; 
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] Exception\n");
            return NULL;
        }
    }
    return NULL;
}

PVOID SsdtUtils::GetKernelBaseAddress() {

    PLIST_ENTRY listEntry = PsLoadedModuleList;

    if (!listEntry) {
        DbgPrint("PsLoadedModuleList is NULL.\n");
        return nullptr;
    }

    auto firstEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    return firstEntry->DllBase;
}

VOID SsdtUtils::VisitSSDT(PVOID kiServiceTable, ULONG numberOfServices) {

	for (int i = 0; i < (int)numberOfServices; i++) {

        __try {
            ULONG offset = (*(PLONG)((DWORD64)kiServiceTable + 4 * i));

            if (offset != 0) {

			    ULONGLONG functionAddress = (ULONGLONG)((DWORD64)kiServiceTable + ((ULONG)offset >> 4));
                
				PCUNICODE_STRING functionName = GetFunctionNameFromMap(&exportsMap, (PVOID)functionAddress);

				if (functionName) {
					DbgPrint("%i - %ws - %p\n", i, functionName->Buffer, functionAddress);
				}
            }
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("[-] Exception\n");
		}
	}
}

FUNCTION_MAP SsdtUtils::GetAndStoreKernelExports(PVOID moduleBase) {

    FUNCTION_MAP exportsMap;

    InitializeFunctionMap(&exportsMap);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + dosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER64 optionalHeader = &ntHeaders->OptionalHeader;
    PIMAGE_DATA_DIRECTORY exportDirectoryData = &optionalHeader->DataDirectory[0];
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + exportDirectoryData->VirtualAddress);

    ULONG* addressOfFunctions = (ULONG*)((PUCHAR)moduleBase + exportDirectory->AddressOfFunctions);
    ULONG* addressOfNames = (ULONG*)((PUCHAR)moduleBase + exportDirectory->AddressOfNames);
    USHORT* addressOfNameOrdinals = (USHORT*)((PUCHAR)moduleBase + exportDirectory->AddressOfNameOrdinals);

    for (ULONG i = 0; i < exportDirectory->NumberOfFunctions; i++) {

        PCHAR functionName = (PCHAR)((PUCHAR)moduleBase + addressOfNames[i]);
        PVOID functionAddress = (PVOID)((PUCHAR)moduleBase + addressOfFunctions[addressOfNameOrdinals[i]]);

        UNICODE_STRING unicodeStringFuncName = { 0 };
        ANSI_STRING ansiStringFuncName;

        RtlInitAnsiString(&ansiStringFuncName, functionName);

        NTSTATUS status = RtlAnsiStringToUnicodeString(&unicodeStringFuncName, &ansiStringFuncName, TRUE);

        if (!NT_SUCCESS(status)) {
            DbgPrint("Failed to convert ANSI string to Unicode string: 0x%x\n", status);
        }

		//DbgPrint("Function: %ws\n", unicodeStringFuncName.Buffer);

        AddFunctionToMap(&exportsMap, functionAddress, &unicodeStringFuncName);
        RtlFreeUnicodeString(&unicodeStringFuncName);
	}

 //   PUNICODE_STRING ZwAllocateVirtualMemoryAddr = GetFunctionNameFromMap(&exportsMap, (PVOID)0xFFFFF800593FB0A0);

	//DbgPrint("ZwAllocateVirtualMemory: %ws\n", ZwAllocateVirtualMemoryAddr->Buffer);

	return exportsMap;
}


VOID SsdtUtils::ParseSSDT() {

    //__try {

    //    ULONGLONG kiSystemUser = LeakKiSystemServiceUser();
    //    DbgPrint("[+] KiSystemServiceUser: %llx\n", kiSystemUser);

    //    ULONGLONG keServiceDescriptorTable = LeakKeServiceDescriptorTable(kiSystemUser);
    //    DbgPrint("[+] KeServiceDescriptorTable: %llx\n", keServiceDescriptorTable);


    //        PSERVICE_DESCRIPTOR_TABLE serviceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)keServiceDescriptorTable;

    //        if (!MmIsAddressValid(&serviceDescriptorTable->NumberOfServices)) {
    //            DbgPrint("[-] NumberOfServices field is invalid\n");
    //            return ssdtMap;
    //        }

    //        ULONG numberOfServices = (ULONG)serviceDescriptorTable->NumberOfServices;
    //        DbgPrint("[+] NumberOfServices: %lu\n", numberOfServices);

    //        if (!MmIsAddressValid(serviceDescriptorTable->ServiceTableBase)) {
    //            DbgPrint("[-] ServiceTableBase is invalid\n");
    //            return ssdtMap;
    //        }

    //        PULONG serviceTable = (PULONG)serviceDescriptorTable->ServiceTableBase;

    //        for (ULONG i = 0; i < numberOfServices; i++) {

    //            __try {

    //                if (!MmIsAddressValid((PVOID)((DWORD64)serviceTable + 4 * i))) {
    //                    DbgPrint("[-] Invalid service table entry at index %lu\n", i);
    //                    continue;
    //                }

    //                ULONG offset = (*(PLONG)((DWORD64)serviceTable + 4 * i));

    //                if (offset != 0) {
    //                    ULONGLONG functionAddress = (ULONGLONG)((DWORD64)serviceTable + ((ULONG)offset >> 4));

    //                    if (!MmIsAddressValid((PVOID)functionAddress)) {
    //                        DbgPrint("[-] Invalid function address at index %lu\n", i);
    //                        continue;
    //                    }

    //                	DbgPrint("%lu - %p\n", i, functionAddress);

    //                //    PUNICODE_STRING functionName = GetFunctionNameFromMap(&exportsMap, (PVOID)functionAddress);

    //                //    if (functionName && functionName->Buffer) {

    //                //        DbgPrint("%lu - %ws - %p\n", i, functionName->Buffer, functionAddress);

    //                ///*        if (!AddSSNToMap(&ssdtMap, i, (PVOID)functionAddress, functionName)) {
    //                //            DbgPrint("[-] Failed to add entry to SSDT map\n");
    //                //        }*/
    //                //    }
    //                //    else {
    //                //        DbgPrint("%lu - Unknown Function - %p\n", i, functionAddress);
    //                //    }

    //       /*         }
    //            }
    //            __except (EXCEPTION_EXECUTE_HANDLER) {
    //                DbgPrint("[-] Exception while processing SSN %lu\n", i);
    //            }
    //        }
    //    }*/
    //}
    //__except (EXCEPTION_EXECUTE_HANDLER) {
    //    DbgPrint("[-] Exception in ParseSSDT\n");
    //}
}


//
//PCWSTR SsdtUtils::getFunctionName(PVOID address) {
//	return FindFunctionName(&exportsMap, address);
//}


// getSsdtUtils
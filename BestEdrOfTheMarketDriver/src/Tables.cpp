#include "Globals.h"

PSSDT_TABLE InitializeSsdtTable(ULONG numberOfServices) {

	PSSDT_TABLE ssdtTable = (PSSDT_TABLE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SSDT_TABLE), 'tdSS');
	if (!ssdtTable) {
		DbgPrint("[-] Failed to allocate memory for SSDT table\n");
		return NULL;
	}

	ssdtTable->NumberOfEntries = numberOfServices;
	ssdtTable->Entries = (PSSDT_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SSDT_ENTRY) * numberOfServices, 'entS');
	if (!ssdtTable->Entries) {
		DbgPrint("[-] Failed to allocate memory for SSDT entries\n");
		ExFreePool(ssdtTable);
		return NULL;
	}

	RtlZeroMemory(ssdtTable->Entries, sizeof(SSDT_ENTRY) * numberOfServices);
	return ssdtTable;
}

VOID PrintSsdtTable(PSSDT_TABLE ssdtTable) {
	if (!ssdtTable || !ssdtTable->Entries) {
		DbgPrint("[-] Invalid SSDT table\n");
		return;
	}

	for (ULONG i = 0; i < ssdtTable->NumberOfEntries; i++) {
		DbgPrint("SSN: %lu, Function Address: %p\n",
			ssdtTable->Entries[i].SSN,
			ssdtTable->Entries[i].FunctionAddress);
	}
}

VOID FreeSsdtTable(PSSDT_TABLE ssdtTable) {
	if (!ssdtTable) {
		return;
	}

	if (ssdtTable->Entries) {
		ExFreePool(ssdtTable->Entries);
	}

	ExFreePool(ssdtTable);
}

PVOID GetFunctionAddressBySSN(PSSDT_TABLE ssdtTable, ULONG ssn) {

	if (!ssdtTable || !ssdtTable->Entries) {
		DbgPrint("[-] Invalid SSDT table\n");
		return NULL;
	}

	if (ssn >= ssdtTable->NumberOfEntries) {
		DbgPrint("[-] SSN %lu is out of range (max: %lu)\n", ssn, ssdtTable->NumberOfEntries - 1);
		return NULL;
	}

	return ssdtTable->Entries[ssn].FunctionAddress;
}

ULONG getSSNByName(
	PSSDT_TABLE ssdtTable, 
	UNICODE_STRING* functionName,
	PFUNCTION_MAP g_exportsMap
) {
	if (!ssdtTable || !ssdtTable->Entries) {
		DbgPrint("[-] Invalid SSDT table\n");
		return -1;
	}

	for (ULONG i = 0; i < ssdtTable->NumberOfEntries; i++) {
		UNICODE_STRING* currentFunctionName = GetFunctionNameFromMap(g_exportsMap, ssdtTable->Entries[i].FunctionAddress);
		if (currentFunctionName == NULL) {
			continue;
		}

		if (RtlCompareUnicodeString(currentFunctionName, functionName, TRUE) == 0) {
			return i;
		}
	}

	return -1;
}
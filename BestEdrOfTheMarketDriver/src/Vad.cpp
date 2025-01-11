#include "Globals.h"

VadUtils::VadUtils() {

	process = NULL;
	root = NULL;
}

VadUtils::VadUtils(PEPROCESS pEprocess) {
	
	process = pEprocess;
	
	root = (PRTL_AVL_TREE)((PUCHAR)pEprocess + EPROCESS_VAD_ROOT_OFFSET);

	if (!MmIsAddressValid(root)) {

		DbgPrint("[!] Invalid VadRoot address: %p\n", root);
	}
}

BOOLEAN VadUtils::isAddressOutOfNtdll(
	RTL_BALANCED_NODE* node,
	ULONG64 targetAddress,
	BOOLEAN* isWow64,
	BOOLEAN* isOutOfSys32Ntdll,
	BOOLEAN* isOutOfWow64Ntdll
) {

	if (node == NULL) {
		return FALSE;
	}

	PMMVAD Vad = (PMMVAD)node;
	if (Vad == NULL || !MmIsAddressValid(Vad))
	{
		return FALSE;
	}

	__try {
		_SUBSECTION* subsectionAddr = (_SUBSECTION*)*(PVOID*)((PUCHAR)Vad + VAD_SUBSECTION_OFFSET);

		if (MmIsAddressValid(subsectionAddr)) {
			PVOID ControlAreaAddr = *(PVOID*)(((PUCHAR)subsectionAddr + VAD_CONTROL_AREA_OFFSET));

			if (MmIsAddressValid(ControlAreaAddr))
			{
				_SEGMENT* segmentAddr = *(_SEGMENT**)(((PUCHAR)ControlAreaAddr + VAD_SEGMENT_OFFSET));

				if (MmIsAddressValid(segmentAddr)) {

					PVOID filePointer = (PVOID*)((PUCHAR)ControlAreaAddr + VAD_FILE_POINTER_OFFSET);
					PVOID fileObjectPointer = *(PVOID*)filePointer;

					FILE_OBJECT* fileObject = (FILE_OBJECT*)NullifyLastDigit((ULONG64)fileObjectPointer);

					if (MmIsAddressValid(fileObject)) {

						if (!*isWow64 && UnicodeStringContains(&fileObject->FileName, L"\\Windows\\System32\\ntdll.dll")) {

							ULONG64 targetVpn = GetUserModeAddressVpn(targetAddress);
							ULONG64 vadStartingVpn = Vad->StartingVpn;
							ULONG64 vadEndingVpn = Vad->EndingVpn;

							if (!(targetVpn > vadStartingVpn && targetVpn < vadEndingVpn)) {
								*isOutOfSys32Ntdll = TRUE;
							}

						}
						else if (*isWow64 && UnicodeStringContains(&fileObject->FileName, L"\\Windows\\SysWOW64\\ntdll.dll")) {

							ULONG32 targetVpn = (ULONG32)GetWow64UserModeAddressVpn(targetAddress);
							ULONG32 vadStartingVpn = (ULONG32)Vad->StartingVpn;
							ULONG32 vadEndingVpn = (ULONG32)Vad->EndingVpn;

							if (!(targetVpn > vadStartingVpn && targetVpn < vadEndingVpn)) {
								*isOutOfWow64Ntdll = TRUE;
							}
						}
					}
				}
			}
		}

		if (*isOutOfSys32Ntdll && *isOutOfWow64Ntdll) {
			return TRUE;
		}

		isAddressOutOfNtdll(
			node->Left,
			targetAddress,
			isWow64,
			isOutOfSys32Ntdll,
			isOutOfWow64Ntdll
		);

		isAddressOutOfNtdll(
			node->Right,
			targetAddress,
			isWow64,
			isOutOfSys32Ntdll,
			isOutOfWow64Ntdll
		);

		return FALSE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[Exception] isAddressOutOfNtdll\n");
		//DbgBreakPoint();
	}

	return FALSE;
}

BOOLEAN VadUtils::isAddressOutOfSpecificDll(
	RTL_BALANCED_NODE* node,
	ULONG64 targetAddress,
	BOOLEAN* isWow64,
	BOOLEAN* isOutOfSys32Dll,
	BOOLEAN* isOutOfWow64Dll,
	unsigned short* sys32DllPath,
	unsigned short* wow64DllPath
) {
	if (node == NULL) {
		return FALSE;
	}

	PMMVAD Vad = (PMMVAD)node;
	if (Vad == NULL || !MmIsAddressValid(Vad))
	{
		return FALSE;
	}

	__try {
		_SUBSECTION* subsectionAddr = (_SUBSECTION*)*(PVOID*)((PUCHAR)Vad + VAD_SUBSECTION_OFFSET);

		if (MmIsAddressValid(subsectionAddr)) {
			PVOID ControlAreaAddr = *(PVOID*)(((PUCHAR)subsectionAddr + VAD_CONTROL_AREA_OFFSET));

			if (MmIsAddressValid(ControlAreaAddr))
			{
				_SEGMENT* segmentAddr = *(_SEGMENT**)(((PUCHAR)ControlAreaAddr + VAD_SEGMENT_OFFSET));

				if (MmIsAddressValid(segmentAddr)) {

					PVOID filePointer = (PVOID*)((PUCHAR)ControlAreaAddr + VAD_FILE_POINTER_OFFSET);
					PVOID fileObjectPointer = *(PVOID*)filePointer;

					FILE_OBJECT* fileObject = (FILE_OBJECT*)NullifyLastDigit((ULONG64)fileObjectPointer);

					if (MmIsAddressValid(fileObject)) {

						if (!*isWow64 && UnicodeStringContains(&fileObject->FileName, sys32DllPath)) {

							ULONG64 targetVpn = GetUserModeAddressVpn(targetAddress);
							ULONG64 vadStartingVpn = Vad->StartingVpn;
							ULONG64 vadEndingVpn = Vad->EndingVpn;

							if (!(targetVpn > vadStartingVpn && targetVpn < vadEndingVpn)) {
								*isOutOfSys32Dll = TRUE;
							}

						}
						else if (*isWow64 && UnicodeStringContains(&fileObject->FileName, wow64DllPath)) {

							ULONG32 targetVpn = (ULONG32)GetWow64UserModeAddressVpn(targetAddress);
							ULONG32 vadStartingVpn = (ULONG32)Vad->StartingVpn;
							ULONG32 vadEndingVpn = (ULONG32)Vad->EndingVpn;

							if (!(targetVpn > vadStartingVpn && targetVpn < vadEndingVpn)) {
								*isOutOfWow64Dll = TRUE;
							}
						}
					}
				}
			}
		}

		if (*isOutOfSys32Dll && *isOutOfWow64Dll) {
			return TRUE;
		}

		isAddressOutOfSpecificDll(
			node->Left,
			targetAddress,
			isWow64,
			isOutOfSys32Dll,
			isOutOfWow64Dll,
			sys32DllPath,
			wow64DllPath
		);

		isAddressOutOfSpecificDll(
			node->Right,
			targetAddress,
			isWow64,
			isOutOfSys32Dll,
			isOutOfWow64Dll,
			sys32DllPath,
			wow64DllPath
		);

		return FALSE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[Exception] isAddressOutOfNtdll\n");
		//DbgBreakPoint();
	}

	return FALSE;
}

BOOLEAN VadUtils::isVadImageAddrIdenticalToLdr(PEPROCESS eProcess, ULONG64 vpnStart) {
	
	KAPC_STATE ApcState;
	NTSTATUS Status;

	PVOID PebAddress = NULL;
	PVOID LdrAddress = NULL;

	KeStackAttachProcess(eProcess, &ApcState);

	__try {
		PebAddress = PsGetProcessPeb(eProcess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = GetExceptionCode();
		return FALSE;
	}

	__try {
		RtlCopyMemory(&LdrAddress, (PVOID)((PUCHAR)PebAddress + 0x018), sizeof(PVOID));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = GetExceptionCode();
		DbgPrint("Exception occurred while reading Ldr: %08x\n", Status);
		return FALSE;
	}

	PPEB_LDR_DATA Ldr = (PPEB_LDR_DATA)LdrAddress;
	if (!MmIsAddressValid(Ldr))
	{
		KeUnstackDetachProcess(&ApcState);
		return FALSE;
	}

	LIST_ENTRY* head = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* current = head->Flink;

	PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

	if (vpnStart != GetUserModeAddressVpn((ULONG64)entry->DllBase)) {
		return TRUE;
	}

	KeUnstackDetachProcess(&ApcState);

	return FALSE;
}

VOID VadUtils::exploreVadTreeAndVerifyLdrIngtegrity(
	RTL_BALANCED_NODE* node,
	UNICODE_STRING* searchStr,
	BOOLEAN* isTampered
) {

	if (node == NULL) {
		return;
	}

	PMMVAD Vad = (PMMVAD)node;
	if (Vad == NULL || !MmIsAddressValid(Vad))
	{
		return;
	}

	__try {

		_SUBSECTION* subsectionAddr = (_SUBSECTION*)*(PVOID*)((PUCHAR)Vad + VAD_SUBSECTION_OFFSET);

		if (MmIsAddressValid(subsectionAddr)) {
			PVOID ControlAreaAddr = *(PVOID*)(((PUCHAR)subsectionAddr + VAD_CONTROL_AREA_OFFSET));

			if (MmIsAddressValid(ControlAreaAddr))
			{
				_SEGMENT* segmentAddr = *(_SEGMENT**)(((PUCHAR)ControlAreaAddr + VAD_SEGMENT_OFFSET));

				if (MmIsAddressValid(segmentAddr)) {

					PVOID filePointer = (PVOID*)((PUCHAR)ControlAreaAddr + VAD_FILE_POINTER_OFFSET);
					PVOID fileObjectPointer = *(PVOID*)filePointer;

					FILE_OBJECT* fileObject = (FILE_OBJECT*)NullifyLastDigit((ULONG64)fileObjectPointer);

					if (MmIsAddressValid(fileObject)) {

						if (UnicodeStringContains(&fileObject->FileName, searchStr->Buffer) && FileIsExe(&fileObject->FileName)) {

							*isTampered = isVadImageAddrIdenticalToLdr(PsGetCurrentProcess(), (ULONG64)Vad->StartingVpn);
						}
					}
				}
			}
		}

		if (!*isTampered) {
			exploreVadTreeAndVerifyLdrIngtegrity(node->Left, searchStr, isTampered);
			exploreVadTreeAndVerifyLdrIngtegrity(node->Right, searchStr, isTampered);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("Exception in exploreVadTreeAndVerifyLdrIngtegrity\n");
		//DbgBreakPoint();
	}

}
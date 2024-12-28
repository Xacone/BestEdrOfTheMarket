#include "Globals.h"


NTSTATUS getProcessBaseAddr(HANDLE procId, PVOID* baseAddr, PSIZE_T size) {
	
	PEPROCESS process;
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION processInfo;
	ULONG returnLength;

	status = PsLookupProcessByProcessId(procId, &process);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &processInfo, sizeof(processInfo), &returnLength);
	
	if (!NT_SUCCESS(status)) {
		ObDereferenceObject(process);
		return status;
	}

	__try {
		
		*baseAddr = ((PPEB2)processInfo.PebBaseAddress)->ImageBaseAddress;

		IMAGE_DOS_HEADER dosHeader;
		IMAGE_NT_HEADERS64 ntHeader;

		RtlCopyMemory(&dosHeader, *baseAddr, sizeof(IMAGE_DOS_HEADER));
		RtlCopyMemory(&ntHeader, (PVOID)((ULONG64)*baseAddr + dosHeader.e_lfanew), sizeof(IMAGE_NT_HEADERS64));

		*size = ntHeader.OptionalHeader.SizeOfImage;

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
		ObDereferenceObject(process);
		return status;
	}

	return STATUS_SUCCESS;
}


ULONG64 StackUtils::getStackStartRtl() {

	PVOID stackFrames[MAX_STACK_FRAMES];
	ULONG capturedFrames = RtlWalkFrameChain(stackFrames, MAX_STACK_FRAMES, RTL_WALK_USER_MODE_STACK);

	if (capturedFrames > 0) {
		PVOID firstFrame = stackFrames[capturedFrames - 1];
		return (ULONG64)firstFrame;
	}

	return NULL;
}

ULONG64 StackUtils::getSSP() {

	return __readmsr(MSR_IA32_PL3_SSP);
}

BOOLEAN StackUtils::isStackCorruptedRtlCET() {

	__try {

		PVOID ssp = (PVOID)this->getSSP();
		PVOID stackFrames[MAX_STACK_FRAMES];
		ULONG framesCaptured = RtlWalkFrameChain(stackFrames, MAX_STACK_FRAMES, RTL_WALK_USER_MODE_STACK);
		PVOID shadowStackFrames[MAX_STACK_FRAMES];
		ULONG shadowStackFramesCount = 0;

		DbgPrint("[+] Process: %s\n", PsGetProcessImageFileName(IoGetCurrentProcess()));
		DbgPrint("[+] SSP: %p\n", ssp);

		if ((ssp != 0x0) && (ssp != NULL)) {

			DWORD_PTR actual = (DWORD_PTR)ssp;
			DWORD_PTR lastFrame = NULL;

			if (MmIsAddressValid((PVOID)actual)) {
				do {
					__try {

						if (*(PVOID*)actual == NULL) {
							break;
						}

						lastFrame = (DWORD_PTR)(*(PVOID*)actual);
						shadowStackFrames[shadowStackFramesCount] = (PVOID)(*(PVOID*)actual);
						shadowStackFramesCount += 1;
						actual += sizeof(PVOID);

					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
						DbgPrint("[-] Exception\n");
						break;
					}

				} while (MmIsAddressValid((PVOID)actual));

				if (framesCaptured > 0) {

					if (shadowStackFramesCount != (framesCaptured - 1)) {
						DbgPrint("Il y'a un probleme avc la pile !!!");
					}

					/*	if ((DWORD_PTR)(stackFrames[framesCaptured - 1]) != (DWORD_PTR)lastFrame) {
							return TRUE;
						}*/
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[-] Exception\n");
		return FALSE;
	}

	return FALSE;
}

PVOID StackUtils::forceCETOnCallingProcess() {

	if (PsGetProcessWow64Process(IoGetCurrentProcess()) == NULL) {

		ULONG* flagsPointer = (ULONG*)((ULONG64)IoGetCurrentProcess() + EPROCESS_MITIGATION_FLAGS2_VALUES_OFFSET);

		__try {

			if (MmIsAddressValid(flagsPointer) && MmIsNonPagedSystemAddressValid(flagsPointer)) {

				ULONG currentFlags = *flagsPointer;
				ULONG mask = currentFlags | 0x4000;
				*flagsPointer = mask;
			}
			else {
				DbgPrint("[!] Invalid or paged address\n");
			}
		

		}
		__except (EXCEPTION_EXECUTE_HANDLER) {

			DbgPrint("[-] Exception\n");
			return NULL;
		}

	}

	return NULL;
}
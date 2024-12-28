#include "Globals.h"

PSSDT_TABLE SyscallsUtils::ssdtTable = nullptr;
PFUNCTION_MAP SyscallsUtils::exportsMap = nullptr;
ZwSetInformationProcess SyscallsUtils::pZwSetInformationProcess = nullptr;

ULONG SyscallsUtils::NtAllocId = 0;
ULONG SyscallsUtils::NtProtectId = 0;
ULONG SyscallsUtils::NtWriteId = 0;

BufferQueue* SyscallsUtils::bufQueue = nullptr;
StackUtils* SyscallsUtils::stackUtils = nullptr;

BOOLEAN SyscallsUtils::tracingEnabed() {
	return isTracingEnabled;
}

VOID SyscallsUtils::enableTracing() {
	isTracingEnabled = TRUE;
}

VOID SyscallsUtils::disableTracing() {
	isTracingEnabled = FALSE;
}

VOID SyscallsUtils::InitStackUtils() {

	stackUtils = (StackUtils*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(StackUtils), 'stku');
	if (!stackUtils) {
		DbgPrint("[-] Failed to allocate memory for StackUtils\n");
		return;
	}

}

ULONGLONG SyscallsUtils::LeakPspAltSystemCallHandlers(ULONGLONG rOffset) {

	for (int i = 0; i < 0x100; i++) {
		__try {

			UINT8 sig_bytes[] = { 0x4C, 0x8D, 0x35 };
			ULONGLONG opcodes = *(PULONGLONG)rOffset;

			if (starts_with_signature((ULONGLONG)&opcodes, sig_bytes, sizeof(sig_bytes))) {
				ULONGLONG correctOffset = ((*(PLONGLONG)(rOffset)) >> 24 & 0x0000FFFFFF);
				return rOffset + 7 + correctOffset;
			}
			rOffset += 2;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("[-] Exception\n");
			return NULL;
		}
	}

	return NULL;
};

ULONG a = 0;

BOOLEAN SyscallsUtils::SyscallHandler(PKTRAP_FRAME trapFrame) {

	// pre check 

	PULONG pArg5 = (PULONG)((ULONG_PTR)trapFrame->Rsp + 0x28);
	PULONG pArg6 = (PULONG)((ULONG_PTR)trapFrame->Rsp + 0x30);

	ULONG arg5 = 0;
	ULONG arg6 = 0;

	if (MmIsAddressValid(pArg5)) {
		arg5 = *pArg5;
	}
	else {
		DbgPrint("Invalid address for RSP + 8\n");
		return FALSE;
	}

	if (MmIsAddressValid(pArg6)) {
		arg6 = *pArg6;
	}
	else {
		DbgPrint("Invalid address for RSP + 16\n");
		return FALSE;
	}

	ULONG id = (ULONG)trapFrame->Rax;

	if ((ULONG)id == NtAllocId) {

		NtAllocHandler(
			(HANDLE)trapFrame->Rcx,
			(PVOID*)trapFrame->Rdx,
			trapFrame->R8,
			(SIZE_T*)trapFrame->R9,
			arg5,
			arg6
		);
	}

	else if (id == 0x0050) {			// Win 10 -> Win11 24H2

		NtProtectHandler(
			(HANDLE)trapFrame->Rcx,
			(PVOID)trapFrame->Rdx,
			(SIZE_T*)trapFrame->R8,
			(ULONG)trapFrame->R9,
			(PULONG)arg5
		);
	}
	else if (id == 0x003a) {

		NtWriteHandler(					// Win 10 -> Win11 24H2
			(HANDLE)trapFrame->Rcx,
			(PVOID)trapFrame->Rdx,
			(PVOID)trapFrame->R8,
			(SIZE_T)trapFrame->R9,
			(PSIZE_T)arg6
		);

	}

	return TRUE;
}

BOOLEAN SyscallsUtils::isSyscallDirect(ULONG64 Rip) 
{

	//BOOLEAN isAddressOutOfSystem32Ntdll = FALSE;
	//BOOLEAN isAddressOutOfWow64Ntdll = FALSE;
	//BOOLEAN isWow64 = FALSE;

	//this->getVadutils()->isAddressOutOfNtdll(
	//	(PRTL_BALANCED_NODE)this->getVadutils()->getVadRoot(),
	//	Rip,
	//	&isWow64,
	//	&isAddressOutOfSystem32Ntdll,
	//	&isAddressOutOfWow64Ntdll
	//);


	return FALSE;
}

VOID SyscallsUtils::UnInitAltSyscallHandler() {

	this->disableTracing();

	UNICODE_STRING usPsRegisterAltSystemCallHandler;
	RtlInitUnicodeString(&usPsRegisterAltSystemCallHandler, L"PsRegisterAltSystemCallHandler");
	pPsRegisterAltSystemCallHandler = (PsRegisterAltSystemCallHandler)MmGetSystemRoutineAddress(&usPsRegisterAltSystemCallHandler);

	ULONGLONG pPspAltSystemCallHandlers = LeakPspAltSystemCallHandlers((ULONGLONG)pPsRegisterAltSystemCallHandler);

	DbgPrint("PspAltSystemCallHandlers: %llx\n", pPspAltSystemCallHandlers);

	LONGLONG* pAltSystemCallHandlers = (LONGLONG*)pPspAltSystemCallHandlers;

	if (pAltSystemCallHandlers[1] != 0x0) {
		pAltSystemCallHandlers[1] = 0x0000000000000000;
	}
}

BOOLEAN SyscallsUtils::InitAltSyscallHandler() {

	UNICODE_STRING usPsRegisterAltSystemCallHandler;
	RtlInitUnicodeString(&usPsRegisterAltSystemCallHandler, L"PsRegisterAltSystemCallHandler");
	pPsRegisterAltSystemCallHandler = (PsRegisterAltSystemCallHandler)MmGetSystemRoutineAddress(&usPsRegisterAltSystemCallHandler);

	UNICODE_STRING usZwSetInformationProcess;
	RtlInitUnicodeString(&usZwSetInformationProcess, L"ZwSetInformationProcess");
	pZwSetInformationProcess = (ZwSetInformationProcess)MmGetSystemRoutineAddress(&usZwSetInformationProcess);

	if (MmIsAddressValid(pPsRegisterAltSystemCallHandler)) {

		UNICODE_STRING usPsRegisterAltSystemCallHandler;
		RtlInitUnicodeString(&usPsRegisterAltSystemCallHandler, L"PsRegisterAltSystemCallHandler");
		pPsRegisterAltSystemCallHandler = (PsRegisterAltSystemCallHandler)MmGetSystemRoutineAddress(&usPsRegisterAltSystemCallHandler);

		ULONGLONG pPspAltSystemCallHandlers = LeakPspAltSystemCallHandlers((ULONGLONG)pPsRegisterAltSystemCallHandler);

		LONGLONG* pAltSystemCallHandlers = (LONGLONG*)pPspAltSystemCallHandlers;
		if (pAltSystemCallHandlers[1] == 0) {

			NTSTATUS status = pPsRegisterAltSystemCallHandler((PVOID)SyscallsUtils::SyscallHandler, 1);

			if (NT_SUCCESS(status)) {
				this->enableTracing();
				DbgPrint("[+] Altsyscall handler registered !\n");
				return STATUS_SUCCESS;
			}
			else {
				DbgPrint("[-] Altsyscall handler already registered !\n");
			}
		}
	}
	else {
		DbgPrint("[-] Failed to get PsRegisterAltSystemCallHandler\n");
	}

	return STATUS_UNSUCCESSFUL;
}

BOOLEAN SyscallsUtils::SetInformationAltSystemCall(HANDLE pid) {

	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID clientId;
	HANDLE hProcess;
	HANDLE qwPid;	

	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	clientId.UniqueProcess = (HANDLE)pid;
	clientId.UniqueThread = 0;
	hProcess = 0;

	if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId))) {

		qwPid = (HANDLE)clientId.UniqueProcess;

		if (NT_SUCCESS(pZwSetInformationProcess(
			hProcess,
			0x64,
			&qwPid,
			1
		))) {

			ZwClose(hProcess);
			return STATUS_SUCCESS;
		}
	}

	return STATUS_UNSUCCESSFUL;
}

BOOLEAN SyscallsUtils::UnsetInformationAltSystemCall(HANDLE pid) {

	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID clientId;
	HANDLE hProcess;
	HANDLE qwPid;

	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	clientId.UniqueProcess = (HANDLE)pid;
	clientId.UniqueThread = 0;
	hProcess = 0;

	if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &clientId))) {

		qwPid = (HANDLE)clientId.UniqueProcess;

		if (NT_SUCCESS(pZwSetInformationProcess(
			hProcess,
			0x64,
			&qwPid,
			0
		))) {

			ZwClose(hProcess);
			return STATUS_SUCCESS;
		}
	}

	return STATUS_UNSUCCESSFUL;
}


VOID SyscallsUtils::EnableAltSycallForThread(PETHREAD pEthread) {

	_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)pEthread + KTHREAD_HEADER_OFFSET);
	header->DebugActive = 0x20;
}

VOID SyscallsUtils::DisableAltSycallForThread(PETHREAD pEthread) {

	_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)pEthread + KTHREAD_HEADER_OFFSET);
	header->DebugActive = 0x0;
}

UCHAR SyscallsUtils::GetAltSyscallStateForThread(PETHREAD pEthrad) {

	_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)pEthrad + KTHREAD_HEADER_OFFSET);
	return header->DebugActive;
}

VOID SyscallsUtils::InitExportsMap(PFUNCTION_MAP map) {
	exportsMap = map;
}

VOID SyscallsUtils::InitSsdtTable(PSSDT_TABLE table) {
	ssdtTable = table;
}

VOID SyscallsUtils::InitIds() {

	// TODO : Handle if not exported -> Fixed or -1

	UNICODE_STRING usNtAllocateVirtualMemory;
	RtlInitUnicodeString(&usNtAllocateVirtualMemory, L"NtAllocateVirtualMemory");
	ULONG ssn = getSSNByName(ssdtTable, &usNtAllocateVirtualMemory, exportsMap);
	DbgPrint("[*] NtAllocateVirtualMemory Id: %lu\n", ssn);

	NtAllocId = ssn;
}

VOID SyscallsUtils::NtAllocHandler(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
) {
	if (Protect == PAGE_EXECUTE_READWRITE) {

		stackUtils->forceCETOnCallingProcess();
		stackUtils->isStackCorruptedRtlCET();

		CHAR* message = (CHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, 256, 'tag');

		if (message != NULL) {
			NTSTATUS status = RtlStringCbPrintfA(
				message,
				256,
				"[*] NtAlloc(0x%p, 0x%p, 0x%p, %zu, 0x%x, 0x%x)",
				ProcessHandle,
				*BaseAddress,
				(VOID*)ZeroBits,
				*RegionSize,
				AllocationType,
				Protect
			);

			if (NT_SUCCESS(status)) {
				auto* queue = getBufQueue();
				if (queue != nullptr && !queue->Enqueue(message)) {
					ExFreePoolWithTag(message, 'tag');
				}
			}
			else {
				ExFreePoolWithTag(message, 'tag');
			}
		}
	}
}

VOID SyscallsUtils::NtProtectHandler(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	SIZE_T* NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
) {
	if (NewAccessProtection & PAGE_EXECUTE) {

		stackUtils->forceCETOnCallingProcess();
		stackUtils->isStackCorruptedRtlCET();

		CHAR* message = (CHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, 256, 'tag');

		if (message != NULL) {

			NTSTATUS status = RtlStringCbPrintfA(
				message,
				256,
				"[*] NtProtect(0x%p, 0x%p, %zu, 0x%x, 0x%p)",
				BaseAddress,
				ProcessHandle,
				*NumberOfBytesToProtect,
				NewAccessProtection,
				OldAccessProtection
			);

			if (NT_SUCCESS(status)) {
				if (!getBufQueue()->Enqueue(message)) {
					ExFreePoolWithTag(message, 'tag');
				}
			}
			else {
				ExFreePoolWithTag(message, 'tag');
			}
		}
	}
}

VOID SyscallsUtils::NtWriteHandler(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten
) {
	
	CHAR* message = (CHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, 256, 'tag');

	if (message != NULL) {
		NTSTATUS status = RtlStringCbPrintfA(
			message,
			256,
			"[*] NtWrite(0x%p, 0x%p, 0x%p, %zu, 0x%p)",
			ProcessHandle,
			BaseAddress,
			Buffer,
			NumberOfBytesToWrite,
			NumberOfBytesWritten
		);

		if (NT_SUCCESS(status)) {
			auto* queue = getBufQueue();
			if (queue != nullptr && !queue->Enqueue(message)) {
				ExFreePoolWithTag(message, 'tag');
			}
		}
		else {
			ExFreePoolWithTag(message, 'tag');
		}
	}
}


VOID SyscallsUtils::DisableAltSyscallFromThreads2() {

	NTSTATUS status;
	ULONG bufferSize = 0x10000;
	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, bufferSize, 'prlc');

	int numProcs = 0;
	int numThreads = 0;

	if (!buffer) {
		DbgPrint("[-] Failed to allocate memory for process buffer\n");
		return;
	}

	do {
		status = ZwQuerySystemInformation(0x05, buffer, bufferSize, &bufferSize);

		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePool(buffer);
			buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, bufferSize, 'proc');
			if (!buffer) {
				DbgPrint("[-] Failed to allocate memory for process buffer\n");
				return;
			}
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status)) {
		PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

		do {
			++numProcs;

			for (ULONG j = 0; j < processInfo->NumberOfThreads; j++) {
				++numThreads;
				PETHREAD eThread;
				status = PsLookupThreadByThreadId(processInfo->Threads[j].ClientId.UniqueThread, &eThread);

				if (!NT_SUCCESS(status)) {
					DbgPrint("[-] PsLookupThreadByThreadId failed for ThreadId: %d\n", processInfo->Threads[j].ClientId.UniqueThread);
					continue;
				}

				_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)eThread + KTHREAD_HEADER_OFFSET);
				if (header->DebugActive >= 0x20) {
					header->DebugActive = 0x0;
				}
			}

			UnsetInformationAltSystemCall(processInfo->UniqueProcessId);

			processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);

		} while (processInfo->NextEntryOffset); 

	}
	else {
		DbgPrint("[-] ZwQuerySystemInformation failed with status: %x\n", status);
	}

	ExFreePool(buffer);
}

VOID SyscallsUtils::InitVadUtils() {

	vadUtils = (VadUtils*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(VadUtils), 'vadu');
	if (!vadUtils) {
		DbgPrint("[-] Failed to allocate memory for VadUtils\n");
		return;
	}

}
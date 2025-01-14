#include "Globals.h"

PSSDT_TABLE SyscallsUtils::ssdtTable = nullptr;
PFUNCTION_MAP SyscallsUtils::exportsMap = nullptr;
ZwSetInformationProcess SyscallsUtils::pZwSetInformationProcess = nullptr;
RegionTracker* SyscallsUtils::vmRegionTracker = nullptr;
HANDLE SyscallsUtils::lastNotifedCidStackCorrupt = 0;

// Fixed Syscall IDs from Win10 1507 to Win11 24H2
// Sourced from: https://j00ru.vexillium.org/syscalls/nt/64/

ULONG SyscallsUtils::NtAllocId = 0x0018;
ULONG SyscallsUtils::NtWriteId = 0x003a;
ULONG SyscallsUtils::NtProtectId = 0x0050;
ULONG SyscallsUtils::NtFreeId = 0x001e;
ULONG SyscallsUtils::NtReadId = 0x0006;
ULONG SyscallsUtils::NtWriteFileId = 0x0008;
ULONG SyscallsUtils::NtQueueApcThreadId = 0x0045;
ULONG SyscallsUtils::NtMapViewOfSectionId = 0x0028;
ULONG SyscallsUtils::NtResumeThreadId = 0x0052;
ULONG SyscallsUtils::NtContinueId = 0x0043;

// Variable Syscalls IDs within the same Win versions range

ULONG SyscallsUtils::NtQueueApcThreadExId = 0;				
ULONG SyscallsUtils::NtSetContextThreadId = 0;		    
ULONG SyscallsUtils::NtContinueEx = 0;						

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


VOID SyscallsUtils::NtVersionPreCheck() {

	RTL_OSVERSIONINFOW versionInfo = { 0 };
	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	NTSTATUS status = RtlGetVersion(&versionInfo);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] Failed to get version info\n");
		return;
	}

	switch (versionInfo.dwBuildNumber) {

		case 10240:{
	
			NtQueueApcThreadExId = 0x014b;
			NtSetContextThreadId = 0x016f;

		};
		case 10586:	{

			NtQueueApcThreadExId = 0x014e;
			NtSetContextThreadId = 0x0172;

		};
		case 14393: {

			NtQueueApcThreadExId = 0x0152;
			NtSetContextThreadId = 0x0178;

		};
		case 15063: {

			NtQueueApcThreadExId = 0x0158;
			NtSetContextThreadId = 0x017e;

		};
		case 16299: {

			NtQueueApcThreadExId = 0x015b;
			NtSetContextThreadId = 0x0181;


		};
		case 17134: {

			NtQueueApcThreadExId = 0x015d;
			NtSetContextThreadId = 0x0183;


		};
		case 17763: {

			NtQueueApcThreadExId = 0x015e;
			NtSetContextThreadId = 0x0184;

		};
		case 18362: {

			NtQueueApcThreadExId = 0x015f;
			NtSetContextThreadId = 0x0185;

		};
		case 18363: {

			NtQueueApcThreadExId = 0x015f;
			NtSetContextThreadId = 0x0185;

		};
		case 19041: {

			NtQueueApcThreadExId = 0x0165;
			NtSetContextThreadId = 0x018b;

		};
		case 19042: {

			NtQueueApcThreadExId = 0x0165;
			NtSetContextThreadId = 0x018b;

		};
		case 19043: {

			NtQueueApcThreadExId = 0x0165;
			NtSetContextThreadId = 0x018b;

		};
		case 19044: {

			NtQueueApcThreadExId = 0x0166;
			NtSetContextThreadId = 0x018d;

		};
		case 19045: {

			NtQueueApcThreadExId = 0x0166;
			NtSetContextThreadId = 0x018d;

		};
		case 20348: {

			NtQueueApcThreadExId = 0x016b;
			NtSetContextThreadId = 0x0193;

		};
		case 22000: {

			NtQueueApcThreadExId = 0x016d;
			NtSetContextThreadId = 0x0195;

		};
		case 22621: {

			NtQueueApcThreadExId = 0x0170;
			NtSetContextThreadId = 0x0198;

		};
		case 22631: {

			NtQueueApcThreadExId = 0x0170;
			NtSetContextThreadId = 0x0198;

		};
		case 25000: {

			NtQueueApcThreadExId = 0x0171;
			NtSetContextThreadId = 0x0199;

		};
		case 26000: {

			NtQueueApcThreadExId = 0x0172;
			NtSetContextThreadId = 0x019a;

		};
		default: {

			NtQueueApcThreadExId = 0;
			NtSetContextThreadId = 0;

		};
	}
}

BOOLEAN SyscallsUtils::SyscallHandler(PKTRAP_FRAME trapFrame) {

	PVOID spoofedAddr = NULL;

	ULONG id = (ULONG)trapFrame->Rax;

	if (lastNotifedCidStackCorrupt == PsGetCurrentProcessId()) {
		return FALSE;
	}

	if (id == NtAllocId || id == NtWriteId || id == NtProtectId) {
		
			if(stackUtils->isStackCorruptedRtlCET(&spoofedAddr)) {

			lastNotifedCidStackCorrupt = PsGetCurrentProcessId();

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

			if (kernelNotif) { 

				char* msg = "Corrupted Thread Call Stack";

				SET_WARNING(*kernelNotif);
				SET_SHADOW_STACK_CHECK(*kernelNotif);

				kernelNotif->scoopedAddress = (ULONG64)spoofedAddr;
				kernelNotif->bufSize = sizeof(msg);
				kernelNotif->isPath = FALSE;
				kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
				kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');

				RtlCopyMemory(kernelNotif->procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 15);

				if (kernelNotif->msg) {
					RtlCopyMemory(kernelNotif->msg, msg, strlen(msg) + 1);
					if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
						ExFreePool(kernelNotif->msg);
						ExFreePool(kernelNotif);
					}
				}
				else {
					ExFreePool(kernelNotif);
				}
			}
			return FALSE;
		}
	}
	
	

	PULONGLONG pArg5 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x28);
	PULONGLONG pArg6 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x30);

	ULONGLONG arg5 = 0;
	ULONGLONG arg6 = 0;

	if (MmIsAddressValid(pArg5)) {
		arg5 = *pArg5;
	}

	if (MmIsAddressValid(pArg6)) {
		arg6 = *pArg6;
	}

	if ((ULONG)id == NtAllocId) {		// NtAllocateVirtualMemory

		NtAllocVmHandler(				
			(HANDLE)trapFrame->Rcx,
			(PVOID*)trapFrame->Rdx,
			trapFrame->R8,
			(SIZE_T*)trapFrame->R9,
			(ULONG)arg5,
			(ULONG)arg6
		);
	}
	else if (id == NtResumeThreadId) {   // NtResumeThread

		NtResumeThreadHandler(
			(HANDLE)trapFrame->Rcx,
			(PULONG)trapFrame->Rdx
		);
	}
	else if (id == NtContinueId) {		// NtContinue

		NtContinueHandler(
			(PCONTEXT)trapFrame->Rcx,
			(BOOLEAN)trapFrame->Rdx
		);
	}
	else if (id == 0x0050) {			// NtProtectVirtualMemory | Win 10 -> Win11 24H2

		isSyscallDirect(trapFrame->Rip, "NtProtectVirtualMemory");

		NtProtectVmHandler(
			(HANDLE)trapFrame->Rcx,
			(PVOID)trapFrame->Rdx,
			(SIZE_T*)trapFrame->R8,
			(ULONG)trapFrame->R9,
			(PULONG)arg5
		);
	}
	else if (id == 0x003a) {			// NtWriteVirtualMemory | Win 10 -> Win11 24H2

		isSyscallDirect(trapFrame->Rip, "NtWriteVirtualMemory");

		NtWriteVmHandler(				
			(HANDLE)trapFrame->Rcx,
			(PVOID)trapFrame->Rdx,
			(PVOID)trapFrame->R8,
			(SIZE_T)trapFrame->R9,
			(PSIZE_T)arg6
		);
	}
	else if (id == 0x0045) {			// NtQueueApcThread | Win 10 -> Win11 24H2

		NtQueueApcThreadHandler(
			(HANDLE)trapFrame->Rcx,
			(PPS_APC_ROUTINE)trapFrame->Rdx,
			(PVOID)trapFrame->R8,
			(PVOID)trapFrame->R9,
			(PVOID)arg5
		);
	}
	else if (id == NtQueueApcThreadExId) {		 // NtQueueApcThreadEx

		NtQueueApcThreadExHandler(
			(HANDLE)trapFrame->Rcx,
			(HANDLE)trapFrame->Rdx,
			(PPS_APC_ROUTINE)trapFrame->R8,
			(PVOID)trapFrame->R9,
			(PVOID)arg5,
			(PVOID)arg6
		);

	}
	else if (id == 0x0054) {	        // NtReadVirtualMemory | Win 10 -> Win11 24H2

		isSyscallDirect(trapFrame->Rip, "NtReadVirtualMemory");
	}
	else if (id == 0x0008) {		// NtWriteFile

		PULONGLONG pArg7 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x38);
		PULONGLONG pArg8 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x40);
		PULONGLONG pArg9 = (PULONGLONG)((ULONG_PTR)trapFrame->Rsp + 0x48);

		ULONGLONG arg7 = 0;
		ULONGLONG arg8 = 0;
		ULONGLONG arg9 = 0;

		if (MmIsAddressValid(pArg7)) {
			arg7 = *pArg7;
		}
		else {
			return FALSE;
		}

		if (MmIsAddressValid(pArg8)) {
			arg8 = *pArg8;
		}
		else {
			return FALSE;
		}

		if (MmIsAddressValid(pArg9)) {
			arg9 = *pArg9;
		}
		else {
			return FALSE;
		}

		NtWriteFileHandler(
			(HANDLE)trapFrame->Rcx,
			(HANDLE)trapFrame->Rdx,
			(PIO_APC_ROUTINE)trapFrame->R8,
			(PVOID)trapFrame->R9,
			(PIO_STATUS_BLOCK)arg5,
			(PVOID)arg6,
			(ULONG)arg7,
			(PLARGE_INTEGER)arg8,
			(PULONG)arg9
		);
	}

	return TRUE;
}

BOOLEAN SyscallsUtils::isSyscallDirect(ULONG64 Rip, char* syscallName) 
{
	PEPROCESS curproc = IoGetCurrentProcess();

	PPS_PROTECTION procProtection = PsGetProcessProtection(curproc);

	if (procProtection->Level == 0x0) {

		KAPC_STATE apcState;

		KeStackAttachProcess(curproc, &apcState);

		BYTE op = *(BYTE*)Rip;

		BOOLEAN isWow64 = FALSE;
		BOOLEAN isAddressOutOfSystem32Ntdll = FALSE;
		BOOLEAN isAddressOutOfWow64Ntdll = FALSE;

		RTL_AVL_TREE* root = (RTL_AVL_TREE*)((PUCHAR)IoGetCurrentProcess() + OffsetsMgt::GetOffsets()->VadRoot);

		VadUtils::isAddressOutOfSpecificDll(
			(PRTL_BALANCED_NODE)root,
			(ULONG64)Rip,
			&isWow64,
			&isAddressOutOfSystem32Ntdll,
			&isAddressOutOfWow64Ntdll,
			L"\\Windows\\System32\\ntdll.dll",
			L"\\Windows\\SysWOW64\\ntdll.dll"
		);

		BOOL isSyscallDirect = FALSE;

		if (isWow64) {
			if (isAddressOutOfSystem32Ntdll ^ isAddressOutOfWow64Ntdll) {
				isSyscallDirect = TRUE;
			}
		}

		else {
			isSyscallDirect = isAddressOutOfSystem32Ntdll;
		}

		if (isSyscallDirect && op == 0xC3) {

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

			if (kernelNotif) {

				char* msg = "NT Syscall did not came from Ntdll";

				SET_WARNING(*kernelNotif);
				SET_SYSCALL_CHECK(*kernelNotif);

				kernelNotif->bufSize = sizeof(msg);
				kernelNotif->isPath = FALSE;
				kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
				kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');

				RtlCopyMemory(kernelNotif->procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 15);

				if (kernelNotif->msg) {
					RtlCopyMemory(kernelNotif->msg, msg, strlen(msg) + 1);
					if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
						ExFreePool(kernelNotif->msg);
						ExFreePool(kernelNotif);
					}
				} else {
					ExFreePool(kernelNotif);
				}
			}
		}

		KeUnstackDetachProcess(&apcState);
	}

	return FALSE;
}

VOID SyscallsUtils::UnInitAltSyscallHandler() {

	UNICODE_STRING usPsRegisterAltSystemCallHandler;
	RtlInitUnicodeString(&usPsRegisterAltSystemCallHandler, L"PsRegisterAltSystemCallHandler");
	pPsRegisterAltSystemCallHandler = (PsRegisterAltSystemCallHandler)MmGetSystemRoutineAddress(&usPsRegisterAltSystemCallHandler);

	ULONGLONG pPspAltSystemCallHandlers = LeakPspAltSystemCallHandlers((ULONGLONG)pPsRegisterAltSystemCallHandler);

	DbgPrint("[*] PspAltSystemCallHandlers: %llx\n", pPspAltSystemCallHandlers);

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

	_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)pEthread + OffsetsMgt::GetOffsets()->Header);
	header->DebugActive = 0x20;
}

VOID SyscallsUtils::DisableAltSycallForThread(PETHREAD pEthread) {

	_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)pEthread + 
		OffsetsMgt::GetOffsets()->Header);
	header->DebugActive = 0x0;
}

UCHAR SyscallsUtils::GetAltSyscallStateForThread(PETHREAD pEthrad) {

	_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)pEthrad + OffsetsMgt::GetOffsets()->Header);
	return header->DebugActive;
}

VOID SyscallsUtils::InitExportsMap(PFUNCTION_MAP map) {
	exportsMap = map;
}

VOID SyscallsUtils::InitSsdtTable(PSSDT_TABLE table) {
	ssdtTable = table;
}

VOID SyscallsUtils::InitIds() {

	UNICODE_STRING usNtAllocateVirtualMemory;
	RtlInitUnicodeString(&usNtAllocateVirtualMemory, L"NtAllocateVirtualMemory");
	ULONG ntAllocSsn = getSSNByName(ssdtTable, &usNtAllocateVirtualMemory, exportsMap);

	NtAllocId = ntAllocSsn;

	UNICODE_STRING usNtFreeVirtualMemory;
	RtlInitUnicodeString(&usNtFreeVirtualMemory, L"NtFreeVirtualMemory");
	ULONG ntFreeSsn = getSSNByName(ssdtTable, &usNtFreeVirtualMemory, exportsMap);

	NtFreeId = ntFreeSsn;
}

// Example Handler
VOID SyscallsUtils::NtAllocVmHandler(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
) {

	BOOLEAN Remote;

	if (Protect == 0x40) {  // RWX

		Remote = TRUE;

		if (ProcessHandle == (HANDLE)-1) {
			Remote = FALSE;
		}

		// For future use
	}
}

VOID SyscallsUtils::NtProtectVmHandler(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	SIZE_T* NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
) {

	if (NewAccessProtection & PAGE_EXECUTE) {

		PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, *NumberOfBytesToProtect, 'msg');

		if (buffer) {

			RtlCopyMemory(buffer, BaseAddress, *NumberOfBytesToProtect);

			RAW_BUFFER rawBuf;

			rawBuf.buffer = (BYTE*)buffer;
			rawBuf.size = *NumberOfBytesToProtect;
			rawBuf.pid = PsGetProcessId(PsGetCurrentProcess());
			RtlCopyMemory(rawBuf.procName, PsGetProcessImageFileName(PsGetCurrentProcess()), 15);

			if (!CallbackObjects::GetBytesQueue()->Enqueue(rawBuf)) {
				ExFreePool(rawBuf.buffer);
			}
		}
	}
}

VOID SyscallsUtils::NtWriteVmHandler(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten
) {

	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytesToWrite, 'msg');

	if (buffer) {

		RtlCopyMemory(buffer, Buffer, NumberOfBytesToWrite);

		RAW_BUFFER rawBuf;

		rawBuf.buffer = (BYTE*)buffer;
		rawBuf.size = NumberOfBytesToWrite;
		rawBuf.pid = PsGetProcessId(PsGetCurrentProcess());
		RtlCopyMemory(rawBuf.procName, PsGetProcessImageFileName(PsGetCurrentProcess()), 15);

		if (!CallbackObjects::GetBytesQueue()->Enqueue(rawBuf)) {
			ExFreePool(rawBuf.buffer);
		}
	}
}

VOID SyscallsUtils::NtWriteFileHandler(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID Buffer,
	ULONG Length,
	PLARGE_INTEGER ByteOffset,
	PULONG Key
) {

	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Length, 'msg');

	if (buffer) {

		RtlCopyMemory(buffer, Buffer, Length);

		RAW_BUFFER rawBuf;

		rawBuf.buffer = (BYTE*)buffer;
		rawBuf.size = Length;
		rawBuf.pid = PsGetProcessId(PsGetCurrentProcess());
		RtlCopyMemory(rawBuf.procName, PsGetProcessImageFileName(PsGetCurrentProcess()), 15);

		if (!CallbackObjects::GetBytesQueue()->Enqueue(rawBuf)) {
			ExFreePool(rawBuf.buffer);
		}
	}
}

VOID SyscallsUtils::NtReadVmHandler(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToRead,
	PSIZE_T NumberOfBytesRead
) {

	// For future use

}

VOID SyscallsUtils::NtQueueApcThreadHandler(
	HANDLE ThreadHandle,
	PPS_APC_ROUTINE ApcRoutine,
	PVOID ApcArgument1,
	PVOID ApcArgument2,
	PVOID ApcArgument3
) {

	// For future use

}

VOID SyscallsUtils::NtQueueApcThreadExHandler(
	HANDLE ThreadHandle,
	HANDLE UserApcReserveHandle,
	PPS_APC_ROUTINE ApcRoutine,
	PVOID ApcArgument1,
	PVOID ApcArgument2,
	PVOID ApcArgument3
)
{

	// For future use

}

VOID SyscallsUtils::NtContinueHandler(
	PCONTEXT Context,
	BOOLEAN TestAlert
) {

	// For future use

}

VOID SyscallsUtils::NtResumeThreadHandler(
	HANDLE ThreadHandle,
	PULONG SuspendCount
) {



	// For future use

}

VOID SyscallsUtils::DisableAltSyscallFromThreads2() {

	NTSTATUS status;
	ULONG bufferSize = 0x10000;
	PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, bufferSize, 'prlc');

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
			for (ULONG j = 0; j < processInfo->NumberOfThreads; j++) {

				PETHREAD eThread;
				status = PsLookupThreadByThreadId(processInfo->Threads[j].ClientId.UniqueThread, &eThread);

				if (!NT_SUCCESS(status)) {
					DbgPrint("[-] PsLookupThreadByThreadId failed for ThreadId: %d\n", processInfo->Threads[j].ClientId.UniqueThread);
					continue;
				}

				_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)eThread + OffsetsMgt::GetOffsets()->Header);

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

VOID SyscallsUtils::DisableAltSyscallFromThreads3() {

	__try {

		PEPROCESS currentProcess = PsInitialSystemProcess;
		PLIST_ENTRY listEntry = (PLIST_ENTRY)((PUCHAR)currentProcess + OffsetsMgt::GetOffsets()->ActiveProcessLinks);

		do
		{
			currentProcess = (PEPROCESS)((PUCHAR)listEntry - OffsetsMgt::GetOffsets()->ActiveProcessLinks);

			if (!currentProcess) {
				DbgPrint("[-] Failed to get current process\n");
				break;
			}

			HANDLE pid = PsGetProcessId(currentProcess);
			UnsetInformationAltSystemCall(pid);

			PLIST_ENTRY listEntryThreads = (PLIST_ENTRY)((PUCHAR)currentProcess + OffsetsMgt::GetOffsets()->ThreadListHead);
			PLIST_ENTRY threadListEntry = listEntryThreads->Flink;

			PULONG flags3 = (PULONG)((DWORD64)currentProcess + OffsetsMgt::GetOffsets()->Flags3);

			if (!flags3) {
				DbgPrint("[-] Failed to get flags3\n");
				break;
			}

			*flags3 = *flags3 & 0xFDFFFFFF;

			do {
				__try {

					PETHREAD eThread = (PETHREAD)((PUCHAR)threadListEntry - OffsetsMgt::GetOffsets()->ThreadListEntry);

					if (eThread) {	

						_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)eThread + OffsetsMgt::GetOffsets()->Header);
						
						if (!header || !MmIsAddressValid(header)) {
							break;
						}

						if (header->DebugActive >= 0x20) {

							header->DebugActive = 0x0;
						}

						threadListEntry = threadListEntry->Flink;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrint("[-] Exception in DisableAltSyscallFromThreads3\n");
				}

			} while (threadListEntry != listEntryThreads);

			listEntry = listEntry->Flink;

		} while (listEntry != (PLIST_ENTRY)((PUCHAR)PsInitialSystemProcess + OffsetsMgt::GetOffsets()->ActiveProcessLinks));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[-] Exception in DisableAltSyscallFromThreads3\n");
	}
}

VOID SyscallsUtils::DestroyAltSyscallThreads() {

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

				_DISPATCHER_HEADER* header = (_DISPATCHER_HEADER*)((DWORD64)eThread + OffsetsMgt::GetOffsets()->Header);

				if (header->DebugActive >= 0x20) {
					
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
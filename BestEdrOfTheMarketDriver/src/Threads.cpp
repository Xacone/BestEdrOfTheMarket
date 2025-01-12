#include "Globals.h"

BOOLEAN ThreadUtils::isThreadRemotelyCreated(HANDLE procId) {

	if (PsGetCurrentProcessId() != procId) {
		return TRUE;
	}

	return FALSE;
}

BOOLEAN ThreadUtils::isThreadInjected(ULONG64* addr) {

	BOOLEAN isAddressOutOfSystem32Ntdll = FALSE;
	BOOLEAN isAddressOutOfWow64Ntdll = FALSE;
	BOOLEAN isWow64 = FALSE;

	ULONG64 stackStart = stackUtils.getStackStartRtl();
	if (stackStart == NULL) {
		return FALSE;
	}

	if(((ULONG64)stackStart >> 36) != 0x7FF) {

		if (PsGetProcessWow64Process(PsGetCurrentProcess()) != NULL) {
			isWow64 = TRUE;
		}

		this->getVadUtils()->isAddressOutOfNtdll(
			(PRTL_BALANCED_NODE)this->getVadUtils()->getVadRoot(),
			stackStart,
			&isWow64,
			&isAddressOutOfSystem32Ntdll,
			&isAddressOutOfWow64Ntdll
		);

		*addr = stackStart;

		if (isWow64) {
			if (isAddressOutOfSystem32Ntdll ^ isAddressOutOfWow64Ntdll) {
				return TRUE;
			}
		}
		else {
			return isAddressOutOfSystem32Ntdll;
		}
	}

	return FALSE;
}

VOID ThreadUtils::CreateThreadNotifyRoutine(
	HANDLE ProcessId,
	HANDLE ThreadId,
	BOOLEAN Create
) {
	
	if (Create) {
	
		ULONG64 outAddr;

		SyscallsUtils::SetInformationAltSystemCall(PsGetCurrentProcessId());
			
		SyscallsUtils::EnableAltSycallForThread(PsGetCurrentThread());

		PEPROCESS eProcess;
		NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &eProcess);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] PsLookupProcessByProcessId failed\n");
			return;
		}

		PETHREAD eThread;
		status = PsLookupThreadByThreadId(ThreadId, &eThread);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] PsLookupThreadByThreadId failed\n");
			return;
		}

		ThreadUtils threadUtils = ThreadUtils(
			IoGetCurrentProcess(),
			PsGetCurrentThread()
		);

		if (threadUtils.isProcessImageTampered()) {

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

			if (kernelNotif) {

				char* msg = "Process Image Tampering";

				SET_CRITICAL(*kernelNotif);
				SET_PROC_VAD_CHECK(*kernelNotif);

				kernelNotif->bufSize = sizeof(msg);
				kernelNotif->isPath = FALSE;
				kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
				kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');

				char procName[15];
				RtlCopyMemory(procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 15);
				RtlCopyMemory(kernelNotif->procName, procName, 15);

				if (kernelNotif->msg) {
					RtlCopyMemory(kernelNotif->msg, msg, strlen(msg)+1);
					if (!CallbackObjects::GetNotifQueue()->Enqueue(kernelNotif)) {
						ExFreePool(kernelNotif->msg);
						ExFreePool(kernelNotif);
					}
				}
				else {
					ExFreePool(kernelNotif);
				}
			}
		}

		if (threadUtils.isThreadInjected(&outAddr)) {

			PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

			if (kernelNotif) {

				char* msg = "Injected Thread";

				SET_CRITICAL(*kernelNotif);
				SET_STACK_BASE_VAD_CHECK(*kernelNotif);
				
				kernelNotif->bufSize = sizeof(msg);
				kernelNotif->isPath = FALSE;
				kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
				kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');
				kernelNotif->scoopedAddress = outAddr;

				char procName[15];
				RtlCopyMemory(procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 15);
				RtlCopyMemory(kernelNotif->procName, procName, 15);


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
		}

	}
	else {
		SyscallsUtils::DisableAltSycallForThread(PsGetCurrentThread());
	}
}

VOID ThreadUtils::setThreadNotificationCallback() {

	NTSTATUS status = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] PsSetCreateThreadNotifyRoutine failed\n");
	}
	else {	

		DbgPrint("[+] PsSetCreateThreadNotifyRoutine success\n");
	}
}

VOID ThreadUtils::unsetThreadNotificationCallback() {

	NTSTATUS status = PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] PsRemoveCreateThreadNotifyRoutine failed\n");
	}
	else {

		DbgPrint("[+] PsRemoveCreateThreadNotifyRoutine success\n");
	}
}
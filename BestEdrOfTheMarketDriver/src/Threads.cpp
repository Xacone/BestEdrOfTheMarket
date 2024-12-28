#include "Globals.h"

BOOLEAN ThreadUtils::isThreadRemotelyCreated(HANDLE procId) {

	if (PsGetCurrentProcessId() != procId) {
		return TRUE;
	}

	return FALSE;
}

BOOLEAN ThreadUtils::isThreadInjected() {

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
		} else {
			isWow64 = FALSE;
		}

		this->getVadUtils()->isAddressOutOfNtdll(
			(PRTL_BALANCED_NODE)this->getVadUtils()->getVadRoot(),
			stackStart,
			&isWow64,
			&isAddressOutOfSystem32Ntdll,
			&isAddressOutOfWow64Ntdll
		);

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
			DbgPrint("Process Image Tampered !\n");
			CallbackObjects::GetQueue()->Enqueue(
				"Process Image Tampered !"
			);
		}

		if (threadUtils.isThreadInjected()) {
			DbgPrint("Thread is injected !\n");
			CallbackObjects::GetQueue()->Enqueue(
				"Thread is Injected wazzaaaaaa !"
			);
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
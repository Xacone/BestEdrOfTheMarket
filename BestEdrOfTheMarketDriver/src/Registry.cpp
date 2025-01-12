#include "Globals.h"

LARGE_INTEGER RegistryUtils::cookie = { 0 };

BOOLEAN RegistryUtils::isRegistryPersistenceBehavior(
	PUNICODE_STRING regPath
) {

	if (UnicodeStringContains(regPath, L"\\CurrentVersion\\Run")
		|| UnicodeStringContains(regPath, L"\\CurrentVersion\\RunOnce")
		|| UnicodeStringContains(regPath, L"\\CurrentVersion\\RunOnce\\Setup")
		) {

		return TRUE;
	}
	
	return FALSE;
}

NTSTATUS RegistryUtils::RegOpNotifyCallback(
	PVOID CallbackContext,
	PVOID Arg1,
	PVOID Arg2
) {
	
	NTSTATUS status;
	PREG_POST_OPERATION_INFORMATION queryKeyInfo;
	PREG_QUERY_VALUE_KEY_INFORMATION queryValueInfo;
	PCUNICODE_STRING regPath;
	PUNICODE_STRING imageFileName;

	REG_NOTIFY_CLASS regNotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Arg1;

	switch (regNotifyClass) {
	case RegNtPreCreateKeyEx:

		queryKeyInfo = (PREG_POST_OPERATION_INFORMATION)Arg2;

		if (queryKeyInfo == NULL) {
			break;
		}

		if (queryKeyInfo->Object == NULL || !MmIsAddressValid(queryKeyInfo->Object)) {
			break;
		}

		status = CmCallbackGetKeyObjectIDEx(
			&cookie,
			queryKeyInfo->Object,
			NULL,
			&regPath,
			0
		);

		if (!NT_SUCCESS(status) || regPath == NULL || regPath->Length == 0 || !MmIsAddressValid(regPath->Buffer)) {
			break;
		}

		else {
		
			if (isRegistryPersistenceBehavior((PUNICODE_STRING)regPath)) {

				PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

				if (kernelNotif) {

					char* msg = "Persistence-Like Registry peration";

					SET_WARNING(*kernelNotif);
					SET_SYSCALL_CHECK(*kernelNotif);

					kernelNotif->bufSize = sizeof(msg);
					kernelNotif->isPath = FALSE;
					kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
					kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');

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
		break;

	default:
		break;
	}
	

	return STATUS_SUCCESS;
}

VOID RegistryUtils::setRegistryNotificationCallback() {

	NTSTATUS status;
	UNICODE_STRING altitude = RTL_CONSTANT_STRING(ALTITUDE);

	status = CmRegisterCallbackEx(
		RegistryUtils::RegOpNotifyCallback, 
		&altitude, 
		CallbackObjects::GetDriverObject(),
		NULL, 
		&cookie, 
		NULL
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] CmRegisterCallbackEx failed\n");
		return;
	}

	DbgPrint("[+] CmRegisterCallbackEx success\n");
}

VOID RegistryUtils::unsetRegistryNotificationCallback() {

	NTSTATUS status = CmUnRegisterCallback(cookie);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] CmUnRegisterCallback failed\n");
		return;
	}

	DbgPrint("[+] CmUnRegisterCallback success\n");
}
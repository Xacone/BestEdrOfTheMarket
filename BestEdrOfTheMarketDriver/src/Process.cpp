#include "Globals.h"

BOOLEAN ProcessUtils::isProcessImageTampered() {

	NTSTATUS status;
	BOOLEAN isTampered = FALSE;

	char* fileName = PsGetProcessImageFileName(this->process);

	if (fileName != NULL) {

		ANSI_STRING ansiString;
		RtlInitAnsiString(&ansiString, fileName);

		UNICODE_STRING unicodeString;
		RtlZeroMemory(&unicodeString, sizeof(UNICODE_STRING));

		status = RtlAnsiStringToUnicodeString(&unicodeString, &ansiString, TRUE);

		if (!NT_SUCCESS(status)) {
			DbgPrint("[!] Failed to convert ANSI String to Unicode String !");
			return FALSE;
		}

		vadUtils.exploreVadTreeAndVerifyLdrIngtegrity(
			vadUtils.getVadRoot()->BalancedRoot,
			&unicodeString,
			&isTampered
		);

		RtlFreeUnicodeString(&unicodeString);
	}

	return isTampered;
}

BOOLEAN ProcessUtils::isProcessParentPidSpoofed(
	PPS_CREATE_NOTIFY_INFO CreateInfo
) {
	if (CreateInfo->ParentProcessId != CreateInfo->CreatingThreadId.UniqueProcess) {
		return TRUE;
	}

	return FALSE;
}

BOOLEAN ProcessUtils::isProcessGhosted() {

	SE_AUDIT_PROCESS_CREATION_INFO* SeAuditProcessCreationInfo = (SE_AUDIT_PROCESS_CREATION_INFO*)((PUCHAR)this->process + EPROCESS_SE_AUDIT_PROCESS_CREATION_INFO_OFFSET);

	if (MmIsAddressValid(SeAuditProcessCreationInfo) && SeAuditProcessCreationInfo->ImageFileName != NULL) {	
		if (SeAuditProcessCreationInfo->ImageFileName->Name.Buffer == NULL) {
			return TRUE;
		}
	}

	return FALSE;
}

VOID ProcessUtils::CreateProcessNotifyEx(
	PEPROCESS Process,
	HANDLE handle,
	PPS_CREATE_NOTIFY_INFO CreateInfo
) {

	ProcessUtils procUtils = ProcessUtils(Process);
	
	if (CreateInfo) {

		SyscallsUtils::SetInformationAltSystemCall(PsGetCurrentProcessId());
	
		if (procUtils.isProcessParentPidSpoofed(CreateInfo)) {
			DbgPrint("Ppid Spoofing !\n");
		}

		if (procUtils.isProcessGhosted()) {
			DbgPrint("Ghosted Process !\n");
		}
	
	}
}

VOID ProcessUtils::setProcessNotificationCallback() {

	NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(
		CreateProcessNotifyEx,
		FALSE
	);

	if (!NT_SUCCESS(status)) {
		
		DbgPrint("[-] PsSetCreateProcessNotifyRoutineEx failed\n");
	}
	else {
		DbgPrint("[+] PsSetCreateProcessNotifyRoutineEx success\n");
	}
}

VOID ProcessUtils::unsetProcessNotificationCallback() {

	NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(
		CreateProcessNotifyEx,
		TRUE
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] PsSetCreateProcessNotifyRoutineEx failed\n");
	}
	else {
		DbgPrint("[+] PsSetCreateProcessNotifyRoutineEx success\n");
	}

}
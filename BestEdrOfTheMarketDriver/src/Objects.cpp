#include "Globals.h"

BOOLEAN ObjectUtils::isCredentialDumpAttempt(
	POB_PRE_OPERATION_INFORMATION OpInfo
) {

	PEPROCESS targetProc = (PEPROCESS)OpInfo->Object;
	PUNICODE_STRING targetImageFileName;
	SeLocateProcessImageName(targetProc, &targetImageFileName);

	if ( PsGetProcessId(targetProc) != PsGetProcessId(IoGetCurrentProcess()) ) {

		if (UnicodeStringContains(targetImageFileName, L"lsass.exe") || UnicodeStringContains(targetImageFileName, L"LSASS.exe")) {

			if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE) {

				PEPROCESS callingProc = PsGetCurrentProcess();
				PPS_PROTECTION callingProcProtection = PsGetProcessProtection(callingProc);

				int accessMask = OpInfo->Parameters->CreateHandleInformation.DesiredAccess;

				if (callingProcProtection->Level == 0x0) {

					if (accessMask & PROCESS_VM_READ) {

						OpInfo->Parameters->CreateHandleInformation.DesiredAccess = PROCESS_TERMINATE;
						return TRUE;
					}
				}
			}
		}
	}

	return FALSE;
}

OB_PREOP_CALLBACK_STATUS ObjectUtils::PreOperationCallback(
	PVOID RegContext,
	POB_PRE_OPERATION_INFORMATION OpInfo
) {

	if (isCredentialDumpAttempt(OpInfo)) {

		PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

		if (kernelNotif) {

			char* msg = "Credential Dump Attempt";

			SET_CRITICAL(*kernelNotif);
			SET_OBJECT_CHECK(*kernelNotif);

			kernelNotif->bufSize = sizeof(msg);
			kernelNotif->isPath = FALSE;
			kernelNotif->pid = PsGetProcessId(IoGetCurrentProcess());
			kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, strlen(msg) + 1, 'msg');

			RtlCopyMemory(kernelNotif->procName, PsGetProcessImageFileName(IoGetCurrentProcess()), 15);

			RtlCopyMemory(kernelNotif->targetProcName, PsGetProcessImageFileName((PEPROCESS)OpInfo->Object), 15);
		
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

	return OB_PREOP_SUCCESS;
}

//
//BOOLEAN ObjectUtils::isRemoteContextMapipulation(
//	POB_POST_OPERATION_INFORMATION OpInfo
//) {
//	NTSTATUS status;
//
//	PETHREAD curThread = PsGetCurrentThread();
//	PETHREAD concernedThread = (PETHREAD)OpInfo->Object;
//
//	PEPROCESS curProc = PsGetCurrentProcess();
//	PEPROCESS concernedProcess = IoThreadToProcess(concernedThread);
//
//	char* curprocname = (char*)PsGetProcessImageFileName(curProc);
//	char* targprocname = (char*)PsGetProcessImageFileName(concernedProcess);
//
//	PPS_PROTECTION curProcProtection = PsGetProcessProtection(curProc);
//	HANDLE curProcId = PsGetProcessId(curProc);
//
//	HANDLE parentProc = PsGetProcessInheritedFromUniqueProcessId(curProc);
//
//	PEPROCESS parentProcEproc;
//	status = PsLookupProcessByProcessId(parentProc, &parentProcEproc);
//
//	if (!NT_SUCCESS(status)) {
//		return FALSE;
//	}
//
//	if (parentProcEproc) {
//
//		PPS_PROTECTION parentProcProtection = PsGetProcessProtection(parentProcEproc);
//
//		if (parentProcProtection) {
//			if (curProc != concernedProcess
//				&& curProcProtection->Level == 0x0
//				&& curProcId != (HANDLE)0x4
//			) {
//
//				if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
//
//					if (OpInfo->Parameters->CreateHandleInformation.GrantedAccess & THREAD_SET_CONTEXT) {
//
//						return TRUE;
//					}
//				}
//			}
//		}
//	}
//
//	return FALSE;
//}

//POB_POST_OPERATION_CALLBACK ObjectUtils::PostOperationCallback(
//	PVOID RegContext,
//	POB_POST_OPERATION_INFORMATION OpInfo
//) {
//
//	if (ObjectUtils::isRemoteContextMapipulation(OpInfo)) {
//
//	}
//
//	return 0;
//}

VOID ObjectUtils::setObjectNotificationCallback() {

	NTSTATUS status;

	RtlInitUnicodeString(&altitude, ALTITUDE);

	regPreOpRegistration.ObjectType = PsProcessType;
	regPreOpRegistration.Operations = OB_OPERATION_HANDLE_CREATE;
	regPreOpRegistration.PreOperation = PreOperationCallback;
	regPreOpRegistration.PostOperation = NULL;

	objOpCallbackRegistration1.Version = OB_FLT_REGISTRATION_VERSION;
	objOpCallbackRegistration1.OperationRegistrationCount = 1;
	objOpCallbackRegistration1.Altitude = altitude;
	objOpCallbackRegistration1.RegistrationContext = NULL;
	objOpCallbackRegistration1.OperationRegistration = &regPreOpRegistration;

	status = ObRegisterCallbacks(&objOpCallbackRegistration1, &regHandle1);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] ObRegisterCallbacks 1 failed\n");
	}

	DbgPrint("[+] ObRegisterCallbacks 1 success\n");

	//setThreadContextPostOpOperation.ObjectType = PsThreadType;
	//setThreadContextPostOpOperation.Operations = OB_OPERATION_HANDLE_CREATE;
	//setThreadContextPostOpOperation.PreOperation = NULL;
	//setThreadContextPostOpOperation.PostOperation = (POB_POST_OPERATION_CALLBACK)PostOperationCallback;

	//objOpCallbackRegistration2.Version = OB_FLT_REGISTRATION_VERSION;
	//objOpCallbackRegistration2.OperationRegistrationCount = 1;
	//objOpCallbackRegistration2.Altitude = altitude;
	//objOpCallbackRegistration2.RegistrationContext = NULL;
	//objOpCallbackRegistration2.OperationRegistration = &setThreadContextPostOpOperation;

	//status = ObRegisterCallbacks(&objOpCallbackRegistration2, &regHandle2);

	//if (!NT_SUCCESS(status)) {
	//	DbgPrint("[-] ObRegisterCallbacks 2 failed\n");
	//}

	//DbgPrint("[+] ObRegisterCallbacks 2 success\n");

}

VOID ObjectUtils::unsetObjectNotificationCallback() {
	
	ObUnRegisterCallbacks(regHandle1);
	DbgPrint("[+] ObUnRegisterCallbacks 1 success\n");

	//ObUnRegisterCallbacks(regHandle2);
	//DbgPrint("[+] ObUnRegisterCallbacks 2 success\n");
}


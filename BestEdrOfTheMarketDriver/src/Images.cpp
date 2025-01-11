#include "Globals.h"
#include "sha256utils.h"

KMUTEX ImageUtils::g_HashQueueMutex;

VOID ImageUtils::ImageLoadNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
) {
    if (FullImageName == NULL || FullImageName->Buffer == NULL || ImageInfo == NULL) {
        DbgPrint("[-] Invalid parameters\n");
        return;
    }

    if (ImageInfo->ImageSize == 0) {
        DbgPrint("[-] Image size is zero\n");
        return;
    }

    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;
    BOOLEAN attached = FALSE;

    __try {
        if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &targetProcess))) {
            DbgPrint("[-] PsLookupProcessByProcessId failed\n");
            return;
        }

        KeStackAttachProcess(targetProcess, &apcState);
        attached = TRUE;
    
        __try {

                if (FullImageName && FullImageName->Buffer && FullImageName->Length > 0) {
                    ULONG charBufferSize = FullImageName->Length / sizeof(WCHAR) + 1;
                    char* charBuffer = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, charBufferSize, 'jedb');

                    if (charBuffer) {
                        UNICODE_STRING unicodeString;
                        ANSI_STRING ansiString;

                        RtlInitUnicodeString(&unicodeString, FullImageName->Buffer);
                        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiString, &unicodeString, TRUE))) {

                            RtlCopyMemory(charBuffer, ansiString.Buffer, ansiString.Length);
                            charBuffer[ansiString.Length] = '\0';

							PKERNEL_STRUCTURED_NOTIFICATION kernelNotif = (PKERNEL_STRUCTURED_NOTIFICATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_NOTIFICATION), 'krnl');

                            if (kernelNotif) {

                                SET_INFO(*kernelNotif);

                                kernelNotif->pid = PsGetProcessId(targetProcess);
                                kernelNotif->msg = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, ansiString.Length + 1, 'msg');
								kernelNotif->bufSize = ansiString.Length + 1;

                                if (kernelNotif->msg) {

                                    RtlCopyMemory(kernelNotif->msg, charBuffer, ansiString.Length + 1);
                                    kernelNotif->isPath = TRUE;

                                    if (!CallbackObjects::GetHashQueue()->Enqueue(kernelNotif)) {
                                        ExFreePool(kernelNotif->msg);
                                        ExFreePool(kernelNotif);
                                    }
                                }
                                else {
                                    ExFreePool(kernelNotif);
                                }
                            }
                           
                            RtlFreeAnsiString(&ansiString);
                        }
                        else {
                            ExFreePool(charBuffer);
                        }
                    }
                
            }
            else {
                DbgPrint("[-] Failed to allocate memory for section data\n");
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[-] Exception in ImageLoadNotifyRoutine\n");
        }

        KeUnstackDetachProcess(&apcState);
        attached = FALSE;
    }
    __finally {
        if (attached) {
            KeUnstackDetachProcess(&apcState);
        }
        if (targetProcess) {
            ObDereferenceObject(targetProcess);
        }
    }
}

VOID ImageUtils::setImageNotificationCallback() {

	NTSTATUS status = PsSetLoadImageNotifyRoutine(ImageLoadNotifyRoutine);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] PsSetLoadImageNotifyRoutine failed\n");
    }
    else {
		DbgPrint("[+] PsSetLoadImageNotifyRoutine success\n");

    }

}

VOID ImageUtils::unsetImageNotificationCallback() {

	NTSTATUS status = PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutine);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] PsRemoveLoadImageNotifyRoutine failed\n");
    }
    else {
		DbgPrint("[+] PsRemoveLoadImageNotifyRoutine success\n");
    }

}
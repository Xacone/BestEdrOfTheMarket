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
            RAW_BUFFER rawBuffer = { 0 };
            rawBuffer.buffer = (BYTE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, ImageInfo->ImageSize, 'txet');
            rawBuffer.size = ImageInfo->ImageSize;

            if (rawBuffer.buffer) {
                RtlCopyMemory(rawBuffer.buffer, ImageInfo->ImageBase, ImageInfo->ImageSize);

                if (!CallbackObjects::GetBytesQueue()->Enqueue(rawBuffer)) {
                    ExFreePool(rawBuffer.buffer);
                }

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

                            if (!CallbackObjects::GetHashQueue()->Enqueue(charBuffer)) {
                                ExFreePool(charBuffer);
                            }

                            RtlFreeAnsiString(&ansiString);
                        }
                        else {
                            ExFreePool(charBuffer);
                        }
                    }
                }

              /*  char* charBuffer = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, FullImageName->Length + 1, 'jedb');

                if (charBuffer) {
                    RtlCopyMemory(charBuffer, FullImageName->Buffer, FullImageName->Length);
                    charBuffer[FullImageName->Length] = '\0';

                    CallbackObjects::GetHashQueue()->Enqueue(charBuffer);
                    
					ExFreePool(charBuffer);
                }*/

			/*	char* buffer = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, FullImageName->Length + 1, 'txet');
                if (buffer) {
                    RtlCopyMemory(buffer, FullImageName->Buffer, FullImageName->Length);
                    buffer[FullImageName->Length] = '\0';
                }*/

                //CallbackObjects::GetHashQueue()->Enqueue(charBuffer);

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

}

VOID ImageUtils::unsetImageNotificationCallback() {

	NTSTATUS status = PsRemoveLoadImageNotifyRoutine(ImageLoadNotifyRoutine);

	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] PsRemoveLoadImageNotifyRoutine failed\n");
	}

}
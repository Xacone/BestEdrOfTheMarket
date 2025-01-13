/*
 ____            _     _____ ____  ____           __   _____ _            __  __            _        _
| __ )  ___  ___| |_  | ____|  _ \|  _ \    ___  / _| |_   _| |__   ___  |  \/  | __ _ _ __| | _____| |_
|  _ \ / _ \/ __| __| |  _| | | | | |_) |  / _ \| |_    | | | '_ \ / _ \ | |\/| |/ _` | '__| |/ / _ \ __|
| |_) |  __/\__ \ |_  | |___| |_| |  _ <  | (_) |  _|   | | | | | |  __/ | |  | | (_| | |  |   <  __/ |_
|____/ \___||___/\__| |_____|____/|_| \_\  \___/|_|     |_| |_| |_|\___| |_|  |_|\__,_|_|  |_|\_\___|\__|

						  https://github.com/Xacone/BestEdrOfTheMarket/

							Made w/ <3 by Yazid - github.com/Xacone
*/


#include "Globals.h"
#include <wdf.h>

PDEVICE_OBJECT DeviceObject = NULL;

SyscallsUtils* g_syscallsUtils;
CallbackObjects* g_callbackObjects;

BufferQueue* g_bufferQueue;
NotifQueue* g_hashQueue;
BytesQueue* g_bytesQueue;


void PrintAsciiTitle()
{
	DbgPrint(" ____            _     _____ ____  ____     ___   __   _____ _          \n");
	DbgPrint("| __ )  ___  ___| |_  | ____|  _ \\|  _ \\   / _ \\ / _| |_   _| |__   ___ \n");
	DbgPrint("|  _ \\ / _ \\/ __| __| |  _| | | | | |_) | | | | | |_    | | | '_ \\ / _ \\\n");
	DbgPrint("| |_) |  __/\\__ \\ |_  | |___| |_| |  _ <  | |_| |  _|   | | | | | |  __/\n");
	DbgPrint("|____/_\\___||___/\\__| |_____|____/|_| \\_\\  \\___/|_|     |_| |_| |_|\\___|     v3\n");
	DbgPrint("|  \\/  | __ _ _ __| | _____| |_                                         \n");
	DbgPrint("| |\\/| |/ _` | '__| |/ / _ \\ __|                                        \n");
	DbgPrint("| |  | | (_| | |  |   <  __/ |_           Yazidou - github.com/Xacone  \n");
	DbgPrint("|_|  |_|\\__,_|_|  |_|\\_\\___|\\__|                                        \n\n");
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {

	UNREFERENCED_PARAMETER(DriverObject);

	//g_syscallsUtils->disableTracing();

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Beotm");
	NTSTATUS status = STATUS_SUCCESS;

	g_callbackObjects->unsetNotificationsGlobal();

	g_syscallsUtils->DisableAltSyscallFromThreads3();

	g_syscallsUtils->UnInitAltSyscallHandler();

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

KSPIN_LOCK g_spinLock;

NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
		
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	__try {

		KIRQL oldIrql;
		
		if (stack->Parameters.DeviceIoControl.IoControlCode == BEOTM_RETRIEVE_DATA_NOTIF) {

			KeAcquireSpinLock(&g_spinLock, &oldIrql);

			if (!g_hashQueue) {
				KeReleaseSpinLock(&g_spinLock, oldIrql);
				DbgPrint("[-] HashQueue is NULL\n");
				status = STATUS_UNSUCCESSFUL;
				__leave;
			}

			if (CallbackObjects::GetNotifQueue()->GetSize() > 0) {

				PKERNEL_STRUCTURED_NOTIFICATION resp = CallbackObjects::GetNotifQueue()->Dequeue();
				KeReleaseSpinLock(&g_spinLock, oldIrql);

				if (!resp || !MmIsAddressValid(resp)) {
					status = STATUS_NO_MORE_ENTRIES;
					__leave;
				}

				size_t respLen = 0;

				__try {
					respLen = SafeStringLength(resp->msg, 64) + 1;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrint("[!] Invalid memory access while calculating resp length\n");
					status = STATUS_INVALID_PARAMETER;
					__leave;
				}

				if (stack->Parameters.DeviceIoControl.OutputBufferLength < respLen) {
					DbgPrint("[!] Output buffer is too small\n");
					status = STATUS_BUFFER_TOO_SMALL;
					__leave;
				}

				ULONG totalSize = sizeof(KERNEL_STRUCTURED_NOTIFICATION) + respLen;

				RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, totalSize);
				RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, resp, sizeof(KERNEL_STRUCTURED_NOTIFICATION));
				RtlCopyMemory((BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(KERNEL_STRUCTURED_NOTIFICATION), resp->msg, respLen);

				Irp->IoStatus.Information = totalSize;
				status = STATUS_SUCCESS;

			}
			else {
				KeReleaseSpinLock(&g_spinLock, oldIrql);
				status = STATUS_NO_MORE_ENTRIES;
			}
		}

		else if (stack->Parameters.DeviceIoControl.IoControlCode == BEOTM_RETRIEVE_DATA_BYTE) {

			KeAcquireSpinLockAtDpcLevel(&g_spinLock);

			if (!g_bytesQueue) {
				KeReleaseSpinLockFromDpcLevel(&g_spinLock);
				DbgPrint("[-] BytesQueue is NULL\n");
				status = STATUS_UNSUCCESSFUL;
				__leave;
			}

			if (g_bytesQueue->GetSize() > 0) {

				BYTE* resp;
				ULONG bytesBufSize;
				char procName[15];

				RAW_BUFFER rawBuffer = CallbackObjects::GetBytesQueue()->Dequeue();
				resp = rawBuffer.buffer;
				bytesBufSize = rawBuffer.size;
				RtlCopyMemory(procName, rawBuffer.procName, 15);

				KeReleaseSpinLockFromDpcLevel(&g_spinLock);

				if (resp == NULL || !MmIsAddressValid(resp)) {
					status = STATUS_NO_MORE_ENTRIES;
					__leave;
				}

				if (stack->Parameters.DeviceIoControl.OutputBufferLength < bytesBufSize) {
					status = STATUS_BUFFER_TOO_SMALL;
					__leave;
				}

				__try {
					if (!resp || bytesBufSize == 0) {
						DbgPrint("[!] Response buffer is NULL or size is zero.\n");
						status = STATUS_NO_MORE_ENTRIES;
						__leave;
					}

					if (!MmIsAddressValid(resp) || !MmIsAddressValid((PVOID)((ULONG_PTR)resp + bytesBufSize - 1))) {
						DbgPrint("[!] Response buffer points to invalid memory.\n");
						status = STATUS_ACCESS_VIOLATION;
						__leave;
					}

					if (!Irp->AssociatedIrp.SystemBuffer || !MmIsAddressValid(Irp->AssociatedIrp.SystemBuffer)) {
						DbgPrint("[!] SystemBuffer pointer is invalid.\n");
						status = STATUS_ACCESS_VIOLATION;
						__leave;
					}

					if (!MmIsAddressValid((PVOID)((ULONG_PTR)Irp->AssociatedIrp.SystemBuffer + stack->Parameters.DeviceIoControl.OutputBufferLength - 1))) {
						DbgPrint("[!] SystemBuffer exceeds valid memory range.\n");
						status = STATUS_ACCESS_VIOLATION;
						__leave;
					}

					if (stack->Parameters.DeviceIoControl.OutputBufferLength < bytesBufSize) {
						DbgPrint("[!] Output buffer is too small for response size.\n");
						status = STATUS_BUFFER_TOO_SMALL;
						__leave;
					}

					PKERNEL_STRUCTURED_BUFFER pKsb = (PKERNEL_STRUCTURED_BUFFER)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURED_BUFFER), 'ksb');

					if (!pKsb) {
						DbgPrint("[-] Failed to allocate memory for KERNEL_STRUCTURED_BUFFER\n");
						status = STATUS_INSUFFICIENT_RESOURCES;
						__leave;
					}

					pKsb->buffer = (BYTE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytesBufSize, 'bufr');
					if (!pKsb->buffer) {
						DbgPrint("[-] Failed to allocate memory for buffer\n");
						ExFreePool(pKsb);
						status = STATUS_INSUFFICIENT_RESOURCES;
						__leave;
					}

					RtlCopyMemory(pKsb->buffer, resp, bytesBufSize);
					pKsb->bufSize = bytesBufSize;
					pKsb->pid = static_cast<UINT32>(reinterpret_cast<uintptr_t>(rawBuffer.pid));

					ULONG totalSize = sizeof(KERNEL_STRUCTURED_BUFFER) + bytesBufSize;

					if (stack->Parameters.DeviceIoControl.OutputBufferLength < totalSize) {
						DbgPrint("[-] Output buffer too small\n");
						ExFreePool(pKsb->buffer);
						ExFreePool(pKsb);
						status = STATUS_BUFFER_TOO_SMALL;
						__leave;
					}

					RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, totalSize);
					RtlCopyMemory(pKsb->procName, rawBuffer.procName, 15);
					RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, pKsb, sizeof(KERNEL_STRUCTURED_BUFFER));
					RtlCopyMemory((BYTE*)Irp->AssociatedIrp.SystemBuffer + sizeof(KERNEL_STRUCTURED_BUFFER), pKsb->buffer, bytesBufSize);

					Irp->IoStatus.Information = totalSize;

					status = STATUS_SUCCESS;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrint("[!] Exception occurred during RtlCopyMemory.\n");
					status = STATUS_UNSUCCESSFUL;
					if (resp) {
						ExFreePool(resp);
					}
				}
			}
			else {
				KeReleaseSpinLockFromDpcLevel(&g_spinLock);
				status = STATUS_NO_MORE_ENTRIES;
			}
		}
		else if (stack->Parameters.DeviceIoControl.IoControlCode == END_THAT_PROCESS) {

			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(UINT32)) {
				status = STATUS_INVALID_PARAMETER;
				__leave;
			}

			NTSTATUS termStatus = TerminateProcess((HANDLE) * (UINT32*)Irp->AssociatedIrp.SystemBuffer);

			if (!NT_SUCCESS(termStatus)) {
				DbgPrint("[-] Failed to terminate process with PID %d\n", (UINT32*)Irp->AssociatedIrp.SystemBuffer);
				status = STATUS_UNSUCCESSFUL;
			}
			else {
				DbgPrint("[+] Process %d terminated\n", (UINT32*)Irp->AssociatedIrp.SystemBuffer);
				status = STATUS_SUCCESS;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[!] Exception occurred in DriverIoControl\n");
		status = STATUS_UNSUCCESSFUL;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	PrintAsciiTitle();

	if (!OffsetsMgt::InitWinStructsOffsets()) {
		DbgPrint("[-] Failed to initialize Win Kernel Structs offsets\n");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("[+] Win Kernel Structs offsets initialized\n");

	UNREFERENCED_PARAMETER(RegistryPath);

	g_bufferQueue = (BufferQueue*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(BufferQueue), 'bufq');

	if (!g_bufferQueue) {

		DbgPrint("[-] Failed to allocate memory for Buffer Queue\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_bufferQueue->Init(MAX_BUFFER_COUNT);

	g_hashQueue = (NotifQueue*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(NotifQueue), 'hshq');

	if (!g_hashQueue) {

		DbgPrint("[-] Failed to allocate memory for Hash Queue\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_hashQueue->Init(MAX_BUFFER_COUNT);

	g_bytesQueue = (BytesQueue*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(BytesQueue), 'bytq');

	if (!g_bytesQueue) {

		DbgPrint("[-] Failed to allocate memory for Bytes Queue\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_bytesQueue->Init(MAX_BUFFER_COUNT);

	DriverObject->DriverUnload = UnloadDriver;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

	g_syscallsUtils = (SyscallsUtils*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(SyscallsUtils), 'sysc');
	if (!g_syscallsUtils) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_syscallsUtils->NtVersionPreCheck();
	g_syscallsUtils->InitIds();
	g_syscallsUtils->InitAltSyscallHandler();
	g_syscallsUtils->InitQueue(g_bufferQueue);
	g_syscallsUtils->InitVadUtils();
	g_syscallsUtils->InitStackUtils();

	g_callbackObjects = (CallbackObjects*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(CallbackObjects), 'cbob');

	if (!g_callbackObjects) {

		DbgPrint("[-] Failed to allocate memory for CallbackObjects\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_callbackObjects->InitDriverObject(DriverObject);
	g_callbackObjects->InitializeHashQueueMutex();
	g_callbackObjects->InitNotifQueue(g_hashQueue);
	g_callbackObjects->InitBytesQueue(g_bytesQueue);
	g_callbackObjects->InitBufferQueue(g_bufferQueue);

	g_callbackObjects->setupNotificationsGlobal();

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\Beotm");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Beotm");

	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_NETWORK, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(DeviceObject);
		return status;
	}

	DbgPrint("[+] Driver loaded\n");

	return STATUS_SUCCESS;
}
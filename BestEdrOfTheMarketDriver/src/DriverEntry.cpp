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

PFUNCTION_MAP g_exportsMap;
PSSDT_TABLE g_ssdtTable;

SsdtUtils* g_ssdtUtils;
SyscallsUtils* g_syscallsUtils;
CallbackObjects* g_callbackObjects;
Controller* g_controller;

BufferQueue* g_bufferQueue; 
HashQueue* g_hashQueue;
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

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\BeotmTest2");
	NTSTATUS status = STATUS_SUCCESS;

	g_callbackObjects->unsetNotificationsGlobal();

	g_syscallsUtils->DisableAltSyscallFromThreads3();

	g_syscallsUtils->UnInitAltSyscallHandler();

	//UnitializeWfp();

	//FreeSsdtTable(g_ssdtTable);
	
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

size_t SafeStringLength(const char* str, size_t maxLen) {
	size_t len = 0;
	while (len < maxLen && str[len] != '\0') {
		len++;
	}
	return (len == maxLen) ? maxLen : len;
}

KSPIN_LOCK g_spinLock;

NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	__try {

		KIRQL oldIrql;

		if (stack->Parameters.DeviceIoControl.IoControlCode == BEOTM_RETRIEVE_DATA_BUFFER) {

			KeAcquireSpinLock(&g_spinLock, &oldIrql);

			if (!g_bufferQueue) {
				KeReleaseSpinLock(&g_spinLock, oldIrql);
				DbgPrint("[-] BuffQueue is NULL\n");
				status = STATUS_UNSUCCESSFUL;
				__leave;
			}

			if (g_bufferQueue->GetSize() > 0) {

				PKERNEL_STRUCTURED_NOTIFICATION resp = g_bufferQueue->Dequeue();
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

				RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, resp, respLen);
				Irp->IoStatus.Information = respLen;
			}
			else {
				KeReleaseSpinLock(&g_spinLock, oldIrql);
				status = STATUS_NO_MORE_ENTRIES;
			}
		}

		else if (stack->Parameters.DeviceIoControl.IoControlCode == BEOTM_RETRIEVE_DATA_HASH) {

			KeAcquireSpinLock(&g_spinLock, &oldIrql);

			if (!g_hashQueue) {
				KeReleaseSpinLock(&g_spinLock, oldIrql);
				DbgPrint("[-] HashQueue is NULL\n");
				status = STATUS_UNSUCCESSFUL;
				__leave;
			}

			if (CallbackObjects::GetHashQueue()->GetSize() > 0) {

				PKERNEL_STRUCTURED_NOTIFICATION resp = CallbackObjects::GetHashQueue()->Dequeue();
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

				RAW_BUFFER rawBuffer = CallbackObjects::GetBytesQueue()->Dequeue();
				resp = rawBuffer.buffer;
				bytesBufSize = rawBuffer.size;

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

			NTSTATUS termStatus = TerminateProcess((HANDLE)* (UINT32*)Irp->AssociatedIrp.SystemBuffer);

			if (!NT_SUCCESS(termStatus)) {
				DbgPrint("[-] Failed to terminate process\n");
				status = STATUS_UNSUCCESSFUL;
			}
			else {
				DbgPrint("[+] Process terminated\n");
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

	UNREFERENCED_PARAMETER(RegistryPath);

	g_bufferQueue = (BufferQueue*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(BufferQueue), 'bufq');
	
	if (!g_bufferQueue) {

		DbgPrint("[-] Failed to allocate memory for Buffer Queue\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_bufferQueue->Init(MAX_BUFFER_COUNT);

	g_hashQueue = (HashQueue*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(HashQueue), 'hshq');

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

	//Controller controller = Controller();
	//g_controller = &controller;

	DriverObject->DriverUnload = UnloadDriver;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

	g_ssdtUtils = (SsdtUtils*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(SsdtUtils), 'ssdt');
	if (!g_ssdtUtils) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	g_exportsMap = (PFUNCTION_MAP)&g_ssdtUtils->GetAndStoreKernelExports(g_ssdtUtils->GetKernelBaseAddress());

	g_syscallsUtils = (SyscallsUtils*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(SyscallsUtils), 'sysc');
	if (!g_syscallsUtils) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_syscallsUtils->InitExportsMap(g_exportsMap);
	
	ULONGLONG keServiceDescriptorTable;

	if (isCpuVTxEptSupported()) {
		
		keServiceDescriptorTable = g_ssdtUtils->LeakKeServiceDescriptorTableVPT();
	
	}
	else {
	
		ULONG64 kiSystemServiceUser = SsdtUtils::LeakKiSystemServiceUser();

		keServiceDescriptorTable = SsdtUtils::LeakKeServiceDescriptorTable((ULONG64)kiSystemServiceUser);
	}

	DbgPrint("[+] KeServiceDescriptorTable: %p\n", keServiceDescriptorTable);

	PSERVICE_DESCRIPTOR_TABLE serviceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)keServiceDescriptorTable;

	if (!MmIsAddressValid(&serviceDescriptorTable->NumberOfServices)) {
		DbgPrint("[-] NumberOfServices field is invalid\n");
		return STATUS_UNSUCCESSFUL;
	}

	ULONG numberOfServices = (ULONG)serviceDescriptorTable->NumberOfServices;
	DbgPrint("[+] NumberOfServices: %lu\n", numberOfServices);

	if (!MmIsAddressValid(serviceDescriptorTable->ServiceTableBase)) {
		DbgPrint("[-] ServiceTableBase is invalid\n");
		return STATUS_UNSUCCESSFUL;
	}
		
	PULONG serviceTable = (PULONG)serviceDescriptorTable->ServiceTableBase;

	PSSDT_TABLE pSsdtTable = InitializeSsdtTable(numberOfServices);

	for (ULONG i = 0; i < numberOfServices; i++) {

		if (!MmIsAddressValid((PVOID)((DWORD64)serviceTable + 4 * i))) {
			DbgPrint("[-] Invalid service table entry at index %lu\n", i);
			continue;
		}

		ULONG offset = (*(PLONG)((DWORD64)serviceTable + 4 * i));

		if (offset != 0) {
			ULONGLONG functionAddress = (ULONGLONG)((DWORD64)serviceTable + ((ULONG)offset >> 4));

			if (!MmIsAddressValid((PVOID)functionAddress)) {
				DbgPrint("[-] Invalid function address at index %lu\n", i);
				continue;
			}
				
			pSsdtTable->Entries[i].FunctionAddress = (PVOID)functionAddress;
			pSsdtTable->Entries[i].SSN = i;
				
			UNICODE_STRING* functionName = GetFunctionNameFromMap(g_exportsMap, (PVOID)functionAddress);

			if (functionName == NULL) {
				continue;
			}
		}
	}

	g_syscallsUtils->NtVersionPreCheck();
	//g_syscallsUtils->InitVmRegionTracker();
	g_syscallsUtils->InitSsdtTable(pSsdtTable);
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

	g_callbackObjects->InitializeHashQueueMutex();
	
	g_callbackObjects->InitHashQueue(g_hashQueue);
	g_callbackObjects->InitBytesQueue(g_bytesQueue);
	g_callbackObjects->InitBufferQueue(g_bufferQueue);

	g_callbackObjects->setupNotificationsGlobal();

	DbgPrint("[+] Driver loaded\n");

	/*
	status = InitWfp();

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
		return status;
	}
	*/

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\BeotmTest2");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\BeotmTest2");

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


	return STATUS_SUCCESS;
}
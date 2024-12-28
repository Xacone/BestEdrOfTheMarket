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

VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
		
	UNREFERENCED_PARAMETER(DriverObject);

	g_syscallsUtils->disableTracing();

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\BeotmTest2");
	NTSTATUS status = STATUS_SUCCESS;

	g_callbackObjects->unsetNotificationsGlobal();
	g_syscallsUtils->DisableAltSyscallFromThreads2();
	g_syscallsUtils->UnInitAltSyscallHandler();

	// UnitializeWfp();

	FreeSsdtTable(g_ssdtTable);
	
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

NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	__try {

		if (stack->Parameters.DeviceIoControl.IoControlCode == BEOTM_RETRIEVE_DATA) {

			if (g_bufferQueue->GetSize() > 0) {

				char* resp = g_bufferQueue->Dequeue();
				size_t respLen = strlen(resp) + 1;

				if (stack->Parameters.DeviceIoControl.OutputBufferLength > respLen) {
					
						RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, resp, respLen);
						Irp->IoStatus.Information = respLen;
				
				}
				else {
					DbgPrint("[!] Buffer is too small\n");
				}
			}
	
		}
		else {
			status = STATUS_INVALID_DEVICE_REQUEST;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("ca a pété\n");
		status = STATUS_UNSUCCESSFUL;
	}


	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

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

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

	PrintAsciiTitle();

	UNREFERENCED_PARAMETER(RegistryPath);

	g_bufferQueue = (BufferQueue*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(BufferQueue), 'bufq');
	
	if (!g_bufferQueue) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_bufferQueue->Init(MAX_BUFFER_COUNT);

	//Controller controller = Controller();
	//g_controller = &controller;

	DriverObject->DriverUnload = UnloadDriver;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\BeotmTest2");
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\BeotmTest2");

	//NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_NETWORK, 0, FALSE, &DeviceObject);

	//if (!NT_SUCCESS(status)) {
	//	return status;
	//}

	//status = IoCreateSymbolicLink(&symLink, &devName);
	//if (!NT_SUCCESS(status))
	//{
	//	IoDeleteDevice(DeviceObject);
	//	return status;
	//}

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

	g_syscallsUtils->InitSsdtTable(pSsdtTable);
	g_syscallsUtils->InitIds();
	g_syscallsUtils->InitAltSyscallHandler();
	g_syscallsUtils->InitQueue(g_bufferQueue);
	g_syscallsUtils->InitVadUtils();
	g_syscallsUtils->InitStackUtils();

	g_callbackObjects = (CallbackObjects*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(CallbackObjects), 'cbob');
	if (!g_callbackObjects) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	g_callbackObjects->InitQueue(g_bufferQueue);
	g_callbackObjects->setupNotificationsGlobal();

	DbgPrint("[+] Driver loaded\n");

	/*
	status = InitWfp();

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
		return status;
	}*/

	return STATUS_SUCCESS;
}
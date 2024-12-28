#include <ntifs.h>

extern "C" ULONGLONG __readmsr(ULONG);

typedef NTSTATUS(NTAPI* PsRegisterAltSystemCallHandler)(PVOID HandlerFunction, LONG HandlerIndex);

typedef NTSTATUS(*ZwSetInformationProcess)(
	HANDLE, 
	ULONG, 
	PVOID, 
	ULONG);

extern "C" NTKERNELAPI PLIST_ENTRY PsLoadedModuleList;

extern "C" NTKERNELAPI PEPROCESS PsInitialSystemProcess;

extern "C" NTKERNELAPI PVOID NTAPI MmGetSystemRoutineAddress(
    _In_ PUNICODE_STRING SystemRoutineName
);

extern "C" NTKERNELAPI char* NTAPI PsGetProcessImageFileName(
	_In_ PEPROCESS Process
);

extern "C" NTSTATUS PsSuspendProcess(
	_In_ PEPROCESS Process
);

extern "C" NTSTATUS PsResumeProcess(
	_In_ PEPROCESS Process
);

extern "C" NTSTATUS ZwQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

extern "C" PVOID PsGetProcessWow64Process(
	PEPROCESS Process
);

extern "C" PVOID PsGetProcessPeb(
	PEPROCESS Process
);

extern "C" NTSTATUS ZwQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);



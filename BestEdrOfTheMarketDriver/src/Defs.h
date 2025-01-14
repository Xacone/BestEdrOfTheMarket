#include <ntifs.h>

typedef VOID(NTAPI* PPS_APC_ROUTINE)(
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
	);

typedef NTSTATUS(NTAPI* PsRegisterAltSystemCallHandler)(PVOID HandlerFunction, LONG HandlerIndex);

typedef NTSTATUS(*ZwSetInformationProcess)(
	HANDLE, 
	ULONG, 
	PVOID, 
	ULONG);

extern "C" ULONGLONG __readmsr(ULONG);

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

extern "C" NTSTATUS ZwOpenThread(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
);

extern "C" NTSTATUS PsGetContextThread(
	PETHREAD Thread,
	PCONTEXT ThreadContext,
	KPROCESSOR_MODE PreviousMode
);

extern "C" PPS_PROTECTION PsGetProcessProtection(
	PEPROCESS Process
);

extern "C" HANDLE PsGetProcessInheritedFromUniqueProcessId(
	PEPROCESS Process
);
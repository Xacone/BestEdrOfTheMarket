#include <ntifs.h>

#include <ndis.h>
#include <ndis/nbl.h>

#include <fwpmk.h>
#include <fwpsk.h>
#define INITGUID
#include <guiddef.h>

#include <windef.h>
#include <intrin.h>
#include <ntstrsafe.h>

#include "Structs.h"
#include "Defs.h"
#include "Pe.h"
#include "Offsets.h"

#define MAX_BUFFER_COUNT 256

#pragma comment(lib, "fwpkclnt.lib")
#pragma comment(lib, "ndis.lib")

#pragma warning(disable:4309)
#pragma warning(disable:4245)
#pragma warning(disable: 4244)

#define BEOTM_RETRIEVE_DATA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ProcessAltSystemCallInformation 0x64

#define FORMAT_ADDR(addr) \
	((addr) & 0xFF), ((addr >> 8) & 0xFF), ((addr >> 16) & 0xFF), ((addr >> 24) & 0xFF)

DEFINE_GUID(BEOTM_CALLOUT_GUID,
	0x0bf56436, 0x71e4, 0x4de7, 0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb8, 0xf4);
DEFINE_GUID(BEOTM_SUBLAYER_GUID,
	0xe1d364e8, 0xcd84, 0x4a48, 0xab, 0xa4, 0x60, 0x8c, 0xe8, 0x3e, 0x31, 0xee);

BOOLEAN isCpuVTxEptSupported();

int contains_bytes_bitwise(
	UINT64, 
	const UINT8*, 
	size_t
);

int contains_signature(
	ULONGLONG, 
	size_t, 
	const UINT8*, 
	size_t
);

int starts_with_signature(
	ULONGLONG, 
	const UINT8*, 
	size_t
);

const char* GetProtectionString(
	ULONG
);

VOID InitializeFunctionMap(
	PFUNCTION_MAP
);

VOID AddFunctionToMap(
	PFUNCTION_MAP, 
	PVOID, 
	PUNICODE_STRING
);

UNICODE_STRING* GetFunctionNameFromMap(
	PFUNCTION_MAP, 
	PVOID
);

ULONG HashFunction(
	PVOID
);

VOID FreeFunctionMap(
	PFUNCTION_MAP
);

PSSDT_TABLE InitializeSsdtTable(
	ULONG
);

VOID PrintSsdtTable(
	PSSDT_TABLE
);

VOID FreeSsdtTable(
	PSSDT_TABLE
);

PVOID GetFunctionAddressBySSN(
	PSSDT_TABLE, 
	ULONG
);

ULONG getSSNByName(
	PSSDT_TABLE ssdtTable,
	UNICODE_STRING* functionName,
	PFUNCTION_MAP g_exportsMap
);

ULONG64 NullifyLastDigit(
	ULONG64
);

ULONG64 GetWow64UserModeAddressVpn(
	ULONG64
);

BOOLEAN FileIsExe(
	PUNICODE_STRING
);

BOOLEAN UnicodeStringContains(
	PUNICODE_STRING, 
	PCWSTR
);

const char* GetProtectionTypeString(
	UCHAR
);

const char* GetSignerTypeString(
	UCHAR
);

ULONG64 GetUserModeAddressVpn(
	ULONG64
);

class SsdtUtils;

class ComUtils {

public:

	VOID invertedMsg();

};

class VadUtils {

	PEPROCESS process;
	RTL_AVL_TREE* root;

public:
	
	VadUtils();

	VadUtils(
		PEPROCESS
	);

	//~VadUtils() {}

	VOID addressLookup();

	BOOLEAN isAddressOutOfNtdll(
		RTL_BALANCED_NODE*, 
		ULONG64,
		BOOLEAN*,
		BOOLEAN*,
		BOOLEAN*
	);
	
	VOID exploreVadTreeAndVerifyLdrIngtegrity(
		RTL_BALANCED_NODE*,
		UNICODE_STRING*,
		BOOLEAN*
	);

	BOOLEAN isVadImageAddrIdenticalToLdr(
		PEPROCESS,
		ULONG64
	);

	RTL_AVL_TREE* getVadRoot() {
		return root;
	}

};

class StackUtils {

protected:
	PVOID stackBase;

public:

	ULONG64 getStackStartRtl();
	ULONG64 getSSP();
	BOOLEAN isStackCorruptedRtlCET();
	PVOID forceCETOnCallingProcess();
};


class ThreadTracker {

	THREAD_TRACKER g_ThreadTracker;

public:

	VOID InitializeThreadTracker();

	VOID AddThread(
		HANDLE, 
		HANDLE
	);
	
	VOID RemoveThread(
		HANDLE
	);
};


class WdfTcpipUtils {

	PDEVICE_OBJECT DeviceObject = NULL;
	HANDLE EngineHandle = NULL;
	UINT32 RegCalloutId = 0, AddCalloutId = 0;
	UINT64 FilterId = 0;

public:

	NTSTATUS InitWfp();
	NTSTATUS WfpAddSubLayer();
	NTSTATUS WfpAddFilter();
	NTSTATUS WfpRegisterCallout();
	VOID UnitializeWfp();
	NTSTATUS AddSubLayer();
	
	static VOID TcpipFilteringCallback(
		const FWPS_INCOMING_VALUES*,
		const FWPS_INCOMING_METADATA_VALUES0*,
		PVOID,
		const void*,
		const FWPS_FILTER*,
		UINT64,
		FWPS_CLASSIFY_OUT*
	);
	
	static VOID TcpipFlowDeleteCallback(
		UINT16,
		UINT32,
		UINT64
	);

	static NTSTATUS TcpipNotifyCallback(
		FWPS_CALLOUT_NOTIFY_TYPE,
		const GUID*,
		const FWPS_FILTER*
	);

};

class SsdtUtils {

	FUNCTION_MAP exportsMap;

public:

	SsdtUtils() {}

	~SsdtUtils() {}

	FUNCTION_MAP getFunctionsMap() {
		return exportsMap;
	}
	
	VOID InitExportsMap();
	
	PVOID GetKernelBaseAddress();
	
	VOID VisitSSDT(
		PVOID, 
		ULONG
	);
	
	FUNCTION_MAP GetAndStoreKernelExports(
		PVOID
	);
	
	VOID ParseSSDT();

	ULONGLONG LeakKeServiceDescriptorTableVPT();

	static ULONGLONG LeakKiSystemServiceUser();

	static ULONGLONG LeakKeServiceDescriptorTable(
		ULONGLONG
	);

};


class Queue {

private:

	char** bufferArray;
	ULONG capacity;
	ULONG size;
	ULONG head;
	ULONG tail;
	KSPIN_LOCK spinLock;

public:

	Queue() {}

	VOID Init(ULONG maxBuf) {

		capacity = maxBuf;
		size = 0;
		head = 0;
		tail = 0;

		bufferArray = (char**)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(char*) * capacity, 'qBuf');
		
		if (!bufferArray) {
			DbgPrint("Failed to allocate buffer array\n");
			capacity = 0;
		}

		KeInitializeSpinLock(&spinLock);
	}

	BOOLEAN Enqueue(char* buffer) {
		KIRQL oldIrql;
		KeAcquireSpinLock(&spinLock, &oldIrql);

		if (size == capacity) {
			KeReleaseSpinLock(&spinLock, oldIrql);
			return FALSE;
		}

		bufferArray[tail] = buffer;
		tail = (tail + 1) % capacity;
		size++;

		KeReleaseSpinLock(&spinLock, oldIrql);
		return TRUE;
	}

	char* Dequeue() {
		KIRQL oldIrql;
		KeAcquireSpinLock(&spinLock, &oldIrql);

		if (size == 0) {
			KeReleaseSpinLock(&spinLock, oldIrql);
			return nullptr;
		}

		char* buffer = bufferArray[head];
		head = (head + 1) % capacity;
		size--;

		KeReleaseSpinLock(&spinLock, oldIrql);
		return buffer;
	}

	ULONG GetSize() {
		KIRQL oldIrql;
		KeAcquireSpinLockAtDpcLevel(&spinLock);
		ULONG currentSize = size;
		KeReleaseSpinLockFromDpcLevel(&spinLock);
		return currentSize;
	}

};

class BufferQueue : public Queue {

public:

	BufferQueue() : Queue() {}

};


class HashQueue : public Queue {

public:

	HashQueue() : Queue() {}

};


class SyscallsUtils {

	UNICODE_STRING traced[5];
	PsRegisterAltSystemCallHandler pPsRegisterAltSystemCallHandler;
	BOOLEAN isTracingEnabled;

	static ZwSetInformationProcess pZwSetInformationProcess;

	static PFUNCTION_MAP exportsMap;
	static PSSDT_TABLE ssdtTable;

	static ULONG NtAllocId;
	static ULONG NtWriteId;
	static ULONG NtProtectId;

	static BufferQueue* bufQueue;

	static StackUtils* stackUtils;

	VadUtils* vadUtils;
	
public:

	SyscallsUtils() {} /*: isTracingEnabled(FALSE) {}*/

	ULONGLONG LeakPspAltSystemCallHandlers(
		ULONGLONG
	);
	
	UCHAR GetAltSyscallStateForThread(
		PETHREAD
	);
	
	BOOLEAN InitAltSyscallHandler();

	VOID InitStackUtils();
	
	VOID UnInitAltSyscallHandler();
	
	BOOLEAN tracingEnabed();
	
	VOID enableTracing();
	
	VOID disableTracing();

	VOID DisableAltSyscallFromThreads2();
	
	BOOLEAN isSyscallDirect(
		ULONG64
	);

	BOOLEAN isSyscallIndirect(
		ULONG64
	);

	VOID InitVadUtils();
	
	VOID InitQueue(BufferQueue* queue) {
		bufQueue = queue;
	}

	VadUtils* getVadutils() {
		return vadUtils;
	}

	static VOID NtAllocHandler(
		HANDLE,
		PVOID*,
		ULONG_PTR,
		PSIZE_T,
		ULONG,
		ULONG
	);

	static VOID NtProtectHandler(
		HANDLE,
		PVOID,
		SIZE_T*,
		ULONG,
		PULONG
	);

	static VOID NtWriteHandler(
		HANDLE,
		PVOID,
		PVOID,
		SIZE_T,
		PSIZE_T
	);

	static BOOLEAN SetInformationAltSystemCall(
		HANDLE
	);
	
	static BOOLEAN UnsetInformationAltSystemCall(
		HANDLE
	);
	
	static VOID EnableAltSycallForThread(
		PETHREAD
	);

	static VOID DisableAltSycallForThread(
		PETHREAD
	);

	static VOID InitExportsMap(
		PFUNCTION_MAP
	);

	static VOID InitSsdtTable(
		PSSDT_TABLE
	);
	
	static VOID InitIds();
	
	static BOOLEAN SyscallHandler(
		PKTRAP_FRAME
	);

	static PSSDT_TABLE GetSsdtTable() {
		return ssdtTable;
	}

	static PFUNCTION_MAP GetExportsMap() {
		return exportsMap;
	}

	static BufferQueue* getBufQueue() {
		return bufQueue;
	}
};

class Controller {

public:

	Controller();

	VOID GrantAntiMalwareProtectionToProc(
		PEPROCESS
	);
};

class BehaviorScoring {

	ULONG scoringLevel = 0;

public:

};


class ObjectUtils {

private:
	
	BufferQueue* queue;

public:

	BOOLEAN isHandleOnLsass();

	BOOLEAN isCredentialDumpingAttempt();

	VOID setObjectNotificationCallback();
	VOID unsetObjectNotificationCallback();
};

class ProcessUtils {

private:

	BufferQueue* queue;

	PEPROCESS process;
	VadUtils vadUtils;

public:

	ProcessUtils(PEPROCESS pEprocess) : 
		process(pEprocess),
		vadUtils(process) {
	}

	BOOLEAN isProcessImageTampered();
	
	BOOLEAN isProcessParentPidSpoofed(
		PPS_CREATE_NOTIFY_INFO
	);
	
	BOOLEAN isProcessProtected();
	
	BOOLEAN isProcessSigned();
	
	BOOLEAN InspectPebLdr(
		PEPROCESS, 
		ULONG64
	);
	
	BOOLEAN isProcessGhosted();

	static VOID CreateProcessNotifyEx(
		PEPROCESS,
		HANDLE,
		PPS_CREATE_NOTIFY_INFO
	);

	VOID setProcessNotificationCallback();

	VOID unsetProcessNotificationCallback();

	VadUtils* getVadUtils() {
		return &vadUtils;
	}
};

class ImageUtils {

private:

	BufferQueue* queue;


public:

	BOOLEAN isImageSignatureInvalid(
		PVOID
	);
	
	VOID setImageNotificationCallback();
};

class ThreadUtils : public ProcessUtils {

private:

	PETHREAD thread;
	StackUtils stackUtils;
	BufferQueue* queue;

public:

	ThreadUtils(): ProcessUtils(NULL), thread(NULL) {}

	ThreadUtils(
		PEPROCESS pEprocess, 
		PETHREAD pEthread) : ProcessUtils(pEprocess) {
		
		this->thread = pEthread;
	}

	BOOLEAN isThreadInjected();
	
	BOOLEAN isThreadStackCorruptedCET(
		PETHREAD
	);
	
	BOOLEAN ForceProcessCET(
		PETHREAD
	);

	BOOLEAN isThreadRemotelyCreated(
		HANDLE
	);

	static VOID CreateThreadNotifyRoutine(
		HANDLE,
		HANDLE,
		BOOLEAN
	);

	VOID setThreadNotificationCallback();
	VOID unsetThreadNotificationCallback();
};

class RegistryUtils {

private:
	
	BufferQueue* queue;

public:

	BOOLEAN isRegistryPersistenceBehavior();
	BOOLEAN isSuspiciousInfoQuuery();
	BOOLEAN isSuspiciousKeyEntry();

	VOID setRegistryNotificationCallback();
};

class CallbackObjects :

	public ThreadUtils,
	public RegistryUtils, 
	public ImageUtils,
	public ObjectUtils

{

	static BufferQueue* queue;

public:

	CallbackObjects() {}
	CallbackObjects(
		PEPROCESS
	) {}

	static VOID InitQueue(
		BufferQueue* bufQueue
	) {
		queue = bufQueue;
	}

	static BufferQueue* GetQueue() {
		return queue;
	}

	VOID setupNotificationsGlobal();
	VOID unsetNotificationsGlobal();
};


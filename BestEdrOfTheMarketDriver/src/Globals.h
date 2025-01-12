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

#pragma comment(lib, "fwpkclnt.lib")
#pragma comment(lib, "ndis.lib")

#pragma warning(disable:4309)
#pragma warning(disable:4245)
#pragma warning(disable: 4244)

#define ALTITUDE L"300021"

#define MAX_BUFFER_COUNT 1024
#define HASH_TABLE_SIZE 256

#define BEOTM_RETRIEVE_DATA_NOTIF CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BEOTM_RETRIEVE_DATA_BYTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define END_THAT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x216, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define ProcessAltSystemCallInformation 0x64

#define SHA256_BLOCK_SIZE 32

#define FORMAT_ADDR(addr) \
	((addr) & 0xFF), ((addr >> 8) & 0xFF), ((addr >> 16) & 0xFF), ((addr >> 24) & 0xFF)

DEFINE_GUID(BEOTM_CALLOUT_GUID,
	0x0bf56436, 0x71e4, 0x4de7, 0xbd, 0x0b, 0x1a, 0xf0, 0xb4, 0xcb, 0xb8, 0xf4);
DEFINE_GUID(BEOTM_SUBLAYER_GUID,
	0xe1d364e8, 0xcd84, 0x4a48, 0xab, 0xa4, 0x60, 0x8c, 0xe8, 0x3e, 0x31, 0xee);

BOOLEAN isCpuVTxEptSupported();

size_t SafeStringLength(
	const char*, 
	size_t
);

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

NTSTATUS getProcessBaseAddr(
	HANDLE,
	PVOID*,
	PSIZE_T
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

NTSTATUS TerminateProcess(HANDLE);

char* FetchNtVersion(DWORD);

class OffsetsMgt {
	static KERNEL_STRUCTURES_OFFSET* offsets;

public:
	static BOOLEAN InitWinStructsOffsets();
	static KERNEL_STRUCTURES_OFFSET* GetOffsets() {
		return offsets;
	}
};

class SsdtUtils;
class ComUtils {

public:

	VOID invertedMsg();

};

class VadUtils {

	PEPROCESS process;
	RTL_AVL_TREE* root;
	VAD_RANGE ntdllVadRange;
	VAD_RANGE procVadRange;

public:
	
	VadUtils();

	VadUtils(
		PEPROCESS
	);

	//~VadUtils() {}

	VOID addressLookup();

	static BOOLEAN isAddressOutOfNtdll(
		RTL_BALANCED_NODE*, 
		ULONG64,
		BOOLEAN*,
		BOOLEAN*,
		BOOLEAN*
	);

	static BOOLEAN isAddressOutOfKernelBase(
		RTL_BALANCED_NODE*,
		ULONG64,
		BOOLEAN*,
		BOOLEAN*,
		BOOLEAN*
	);

	static BOOLEAN isAddressOutOfSpecificDll(
		RTL_BALANCED_NODE*,
		ULONG64,
		BOOLEAN*,
		BOOLEAN*,
		BOOLEAN*,
		unsigned short*,
		unsigned short*
	);

	static BOOLEAN isAddressOutOfGdi32(
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

	BOOLEAN isCETEnabled();

	BOOLEAN isCETSupported();

	BOOLEAN isStackCorruptedRtlCET(
		PVOID*
	);

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
	
	ULONGLONG LeakKeServiceDescriptorTableEptRvi();

	static ULONGLONG LeakKiSystemServiceUser();

	static ULONGLONG LeakKeServiceDescriptorTable(
		ULONGLONG
	);

};

class BytesQueue {
private:
	RAW_BUFFER* bufferArray;
	ULONG capacity;
	ULONG size;
	ULONG head;
	ULONG tail;
	KSPIN_LOCK spinLock;

public:
	BytesQueue() : bufferArray(nullptr), capacity(0), size(0), head(0), tail(0) {}

	VOID Init(ULONG maxBuf) {
		capacity = maxBuf;
		size = 0;
		head = 0;
		tail = 0;

		bufferArray = (RAW_BUFFER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(RAW_BUFFER) * capacity, 'qBuf');
		if (!bufferArray) {
			DbgPrint("Failed to allocate buffer array\n");
			capacity = 0;
			return;
		}

		RtlZeroMemory(bufferArray, sizeof(RAW_BUFFER) * capacity);
		KeInitializeSpinLock(&spinLock);
	}

	BOOLEAN Enqueue(RAW_BUFFER rawBuffer) {
		if (!rawBuffer.buffer || rawBuffer.size == 0) {
			DbgPrint("Invalid RAW_BUFFER provided to Enqueue\n");
			return FALSE;
		}

		KIRQL oldIrql;
		KeAcquireSpinLock(&spinLock, &oldIrql);

		if (size == capacity) {
			KeReleaseSpinLock(&spinLock, oldIrql);
			return FALSE;  // Queue is full
		}

		bufferArray[tail] = rawBuffer;
		tail = (tail + 1) % capacity;
		size++;

		//if (size > 0) {
		//	DbgPrint("[Enqueue] Data added successfully\n");
		//}

		KeReleaseSpinLock(&spinLock, oldIrql);
		return TRUE;
	}

	RAW_BUFFER Dequeue() {
		RAW_BUFFER rawBuffer = { nullptr, 0 };

		KIRQL oldIrql;
		KeAcquireSpinLock(&spinLock, &oldIrql);

		if (size == 0) {
			KeReleaseSpinLock(&spinLock, oldIrql);
			return rawBuffer; // Queue is empty
		}

		rawBuffer = bufferArray[head];
		head = (head + 1) % capacity;
		size--;

		//if (size == 0) {
		//	DbgPrint("[Dequeue] Queue is empty now\n");
		//}

		KeReleaseSpinLock(&spinLock, oldIrql);
		return rawBuffer;
	}

	ULONG GetSize() {
		KIRQL oldIrql;
		KeAcquireSpinLockAtDpcLevel(&spinLock);
		ULONG currentSize = size;
		KeReleaseSpinLockFromDpcLevel(&spinLock);
		return currentSize;
	}

	VOID Cleanup() {
		if (bufferArray) {
			ExFreePool(bufferArray);
			bufferArray = nullptr;
		}
		capacity = 0;
		size = 0;
		head = 0;
		tail = 0;
	}

	VOID PrintSizes() {
		KIRQL oldIrql;
		KeAcquireSpinLockAtDpcLevel(&spinLock);
		for (ULONG i = 0; i < size; i++) {
			RAW_BUFFER rb = bufferArray[(head + i) % capacity];
			DbgPrint("\tSize %d: %lu\n", i, rb.size);
		}
		KeReleaseSpinLockFromDpcLevel(&spinLock);
	}

	//~BytesQueue() {
	//	Cleanup();
	//}
};



class BufferQueue {

private:

	PKERNEL_STRUCTURED_NOTIFICATION* bufferArray;
	ULONG capacity;
	ULONG size;
	ULONG head;
	ULONG tail;
	KSPIN_LOCK spinLock;

public:

	BufferQueue() {}

	VOID Init(ULONG maxBuf) {

		capacity = maxBuf;
		size = 0;
		head = 0;
		tail = 0;

		bufferArray = (PKERNEL_STRUCTURED_NOTIFICATION*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PKERNEL_STRUCTURED_NOTIFICATION) * capacity, 'qBuf');

		if (!bufferArray) {
			DbgPrint("Failed to allocate buffer array\n");
			capacity = 0;
		}

		KeInitializeSpinLock(&spinLock);
	}

	BOOLEAN Enqueue(PKERNEL_STRUCTURED_NOTIFICATION buffer) {
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

	PKERNEL_STRUCTURED_NOTIFICATION Dequeue() {
		KIRQL oldIrql;
		KeAcquireSpinLock(&spinLock, &oldIrql);

		if (!bufferArray) {
			KeReleaseSpinLock(&spinLock, oldIrql);
			DbgPrint("Buffer array is null\n");
			return nullptr;
		}

		if (size == 0) {
			KeReleaseSpinLock(&spinLock, oldIrql);
			return nullptr;
		}

		PKERNEL_STRUCTURED_NOTIFICATION buffer = bufferArray[head];
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

class NotifQueue : public BufferQueue {

public:

	NotifQueue() : BufferQueue() {}

};

class RegionTracker {
private:
	LIST_ENTRY HashTable[HASH_TABLE_SIZE];

	ULONG HashFunction(HANDLE ProcessId) {
		return ((ULONG)(ULONG_PTR)ProcessId) % HASH_TABLE_SIZE;
	}

public:

	RegionTracker() {
		for (int i = 0; i < HASH_TABLE_SIZE; i++) {
			InitializeListHead(&HashTable[i]);
		}
	}

	VOID Init() {
		for (int i = 0; i < HASH_TABLE_SIZE; i++) {
			InitializeListHead(&HashTable[i]);
		}
	}

	~RegionTracker() {
		for (int i = 0; i < HASH_TABLE_SIZE; i++) {
			PLIST_ENTRY listHead = &HashTable[i];
			PLIST_ENTRY currentEntry = listHead->Flink;

			while (currentEntry != listHead) {
				PHASH_ENTRY entry = CONTAINING_RECORD(currentEntry, HASH_ENTRY, ListEntry);
				currentEntry = currentEntry->Flink;
				ExFreePoolWithTag(entry, 'tag1');
			}
		}
	}

	VOID AddEntry(HANDLE ProcessId, PVOID address, ULONG size, ULONG Protect, BOOLEAN remote) {
		ULONG hashIndex = HashFunction(ProcessId);
		PHASH_ENTRY newEntry = (PHASH_ENTRY)ExAllocatePool2(NonPagedPool, sizeof(HASH_ENTRY), 'tag1');

		if (newEntry) {
			newEntry->ProcessId = ProcessId;
			newEntry->RegionInfo.address = address;
			newEntry->RegionInfo.size = size;
			newEntry->RegionInfo.Protect = Protect;
			newEntry->RegionInfo.remote = remote;
			InsertHeadList(&HashTable[hashIndex], &newEntry->ListEntry);
			DbgPrint("[+] Added entry for process %p\n", ProcessId);
		}
	}

	PHASH_ENTRY FindEntry(HANDLE ProcessId) {
		ULONG hashIndex = HashFunction(ProcessId);
		PLIST_ENTRY listHead = &HashTable[hashIndex];
		PLIST_ENTRY currentEntry = listHead->Flink;

		while (currentEntry != listHead) {
			PHASH_ENTRY entry = CONTAINING_RECORD(currentEntry, HASH_ENTRY, ListEntry);
			if (entry->ProcessId == ProcessId) {
				return entry;
			}
			currentEntry = currentEntry->Flink;
		}
		return NULL;
	}

	VOID RemoveEntry(HANDLE ProcessId) {
		PHASH_ENTRY entry = FindEntry(ProcessId);
		if (entry) {
			RemoveEntryList(&entry->ListEntry);
			ExFreePoolWithTag(entry, 'tag1');
		}
	}
};


class SyscallsUtils {

	UNICODE_STRING traced[5];
	BOOLEAN isTracingEnabled;

	PsRegisterAltSystemCallHandler pPsRegisterAltSystemCallHandler;

	static ZwSetInformationProcess pZwSetInformationProcess;

	static PFUNCTION_MAP exportsMap;
	static PSSDT_TABLE ssdtTable;

	static ULONG NtAllocId;
	static ULONG NtWriteId;
	static ULONG NtProtectId;
	static ULONG NtFreeId;
	static ULONG NtReadId;
	static ULONG NtWriteFileId;

	// For future use
	static ULONG NtQueueApcThreadId;
	static ULONG NtQueueApcThreadExId;
	static ULONG NtSetContextThreadId;
	static ULONG NtMapViewOfSectionId;
	static ULONG NtResumeThreadId;
	static ULONG NtContinueId;
	static ULONG NtContinueEx;

	static BufferQueue* bufQueue;
	static StackUtils* stackUtils;
	static RegionTracker* vmRegionTracker;

	VadUtils* vadUtils;
	
	static HANDLE lastNotifedCidStackCorrupt;

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

	VOID DisableAltSyscallFromThreads3();
	
	static BOOLEAN isSyscallDirect(
		ULONG64,
		char*
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

	VOID NtVersionPreCheck();


	static VOID NtAllocVmHandler(	// Ok
		HANDLE,
		PVOID*,
		ULONG_PTR,
		PSIZE_T,
		ULONG,
		ULONG
	);

	static VOID NtProtectVmHandler(		// Ok
		HANDLE,
		PVOID,
		SIZE_T*,
		ULONG,
		PULONG
	);

	static VOID NtWriteVmHandler(	// Ok
		HANDLE,
		PVOID,
		PVOID,
		SIZE_T,
		PSIZE_T
	);

	static VOID NtReadVmHandler(	// Ok
		HANDLE,
		PVOID,
		PVOID,
		SIZE_T,
		PSIZE_T
	);

	static VOID NtWriteFileHandler(		// Ok
		HANDLE,
		HANDLE,
		PIO_APC_ROUTINE,
		PVOID,
		PIO_STATUS_BLOCK,
		PVOID,
		ULONG,
		PLARGE_INTEGER,
		PULONG
	);

	static VOID NtQueueApcThreadHandler(
		HANDLE,
		PPS_APC_ROUTINE,
		PVOID,
		PVOID,
		PVOID
	);

	static VOID NtQueueApcThreadExHandler(
		HANDLE,
		HANDLE,
		PPS_APC_ROUTINE,
		PVOID,
		PVOID,
		PVOID
	);

	static VOID NtSetContextThreadHandler(
		HANDLE,
		PVOID
	);

	static VOID NtResumeThreadHandler(
		HANDLE,
		PULONG
	);

	static VOID NtContinueHandler(
		PCONTEXT,
		BOOLEAN
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

	static VOID DestroyAltSyscallThreads();

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

	static VOID InitVmRegionTracker() {

		vmRegionTracker = (RegionTracker*)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(RegionTracker), 'vmrt');

		if (!vmRegionTracker) {
			DbgPrint("Failed to allocate memory for vmRegionTracker\n");
		}

		vmRegionTracker->Init();
	}

	static RegionTracker* getVmRegionTracker() {
		return vmRegionTracker;
	}

};

class ObjectUtils {

private:
	
	UNICODE_STRING altitude;
	
	PVOID regHandle1;
	PVOID regHandle2;

	OB_CALLBACK_REGISTRATION objOpCallbackRegistration1;
	OB_CALLBACK_REGISTRATION objOpCallbackRegistration2;

	OB_OPERATION_REGISTRATION regPreOpRegistration;
	OB_OPERATION_REGISTRATION setThreadContextPostOpOperation;

public:

	VOID setObjectNotificationCallback();
	
	VOID unsetObjectNotificationCallback();

	static OB_PREOP_CALLBACK_STATUS PreOperationCallback(
		PVOID,
		POB_PRE_OPERATION_INFORMATION
	);

	static POB_POST_OPERATION_CALLBACK PostOperationCallback(
		PVOID,
		POB_POST_OPERATION_INFORMATION
	);

	static BOOLEAN isCredentialDumpAttempt(
		POB_PRE_OPERATION_INFORMATION
	);

	static BOOLEAN isRemoteContextMapipulation(
		POB_POST_OPERATION_INFORMATION
	);

};

class ProcessUtils {

private:

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
		
	BOOLEAN isProcessGhosted();

	VOID setProcessNotificationCallback();

	VOID unsetProcessNotificationCallback();

	VadUtils* getVadUtils() {
		return &vadUtils;
	}

	static VOID CreateProcessNotifyEx(
		PEPROCESS,
		HANDLE,
		PPS_CREATE_NOTIFY_INFO
	);
};

class ImageUtils {

private:

	static KMUTEX g_HashQueueMutex;

public:

	VOID InitNotifQueue(NotifQueue*);

	BOOLEAN isImageSignatureInvalid(
		PVOID
	);
	
	static VOID ImageLoadNotifyRoutine(
		PUNICODE_STRING,
		HANDLE,
		PIMAGE_INFO
	);

	VOID setImageNotificationCallback();

	VOID unsetImageNotificationCallback();

	VOID InitializeHashQueueMutex() {
		KeInitializeMutex(&g_HashQueueMutex, 0);
	}
};

class ThreadUtils : public ProcessUtils {

private:

	PETHREAD thread;
	StackUtils stackUtils;

public:

	ThreadUtils(): ProcessUtils(NULL), thread(NULL) {}

	ThreadUtils(
		PEPROCESS pEprocess, 
		PETHREAD pEthread) : ProcessUtils(pEprocess) {
		
		this->thread = pEthread;
	}

	BOOLEAN isThreadInjected(
		ULONG64*
	);
	
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
	
	static LARGE_INTEGER cookie;

public:
	
	VOID setRegistryNotificationCallback();

	VOID unsetRegistryNotificationCallback();

	static NTSTATUS RegOpNotifyCallback(
		PVOID,
		PVOID,
		PVOID
	);

	static BOOLEAN isRegistryPersistenceBehavior(
		PUNICODE_STRING
	);

};

class CallbackObjects :

	public ThreadUtils,
	public RegistryUtils, 
	public ImageUtils,
	public ObjectUtils

{

	static BufferQueue* bufferQueue;
	static NotifQueue* notifQueue;
	static BytesQueue* bytesQueue;

	static PVOID DriverObject;

public:

	CallbackObjects() {}

	CallbackObjects(
		PEPROCESS
	) {}

	static VOID InitDriverObject(PVOID drvObj) {
		DriverObject = drvObj;
	}

	static PVOID GetDriverObject() {
		return DriverObject;
	}

	static VOID InitBufferQueue(
		BufferQueue* bufQueue
	) {
		bufferQueue = bufQueue;
	}

	static VOID InitNotifQueue(
		NotifQueue* ntfQueue
	) {
		notifQueue = ntfQueue;
	}

	static VOID InitBytesQueue(
		BytesQueue* bytQueue
	) {
		bytesQueue = bytQueue;
	}

	static BufferQueue* GetBufferQueue() {
		return bufferQueue;
	}

	static NotifQueue* GetNotifQueue() {
		return notifQueue;
	}

	static BytesQueue* GetBytesQueue() {
		return bytesQueue;
	}

	VOID setupNotificationsGlobal();
	
	VOID unsetNotificationsGlobal();
};


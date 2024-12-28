#include <ntifs.h>

#pragma warning(disable:4201)

#define MM_ZERO_ACCESS         0x0  
#define MM_READONLY            0x1  
#define MM_EXECUTE             0x2  
#define MM_EXECUTE_READ        0x3  
#define MM_READWRITE           0x4  
#define MM_WRITECOPY           0x5  
#define MM_EXECUTE_READWRITE   0x6  
#define MM_EXECUTE_WRITECOPY   0x7  
#define MM_NOACCESS            0x8  
#define MM_GUARD_PAGE          0x9 
#define MM_NOCACHE             0xA 
#define MM_WRITECOMBINE        0xB 
#define MM_EXECUTE_NOCACHE     0xC  
#define MM_EXECUTE_WRITECOMBINE 0xD 
#define MM_EXECUTE_GUARD_PAGE  0xE 
#define MM_EXECUTE_NOACCESS    0xF 

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x4550

#define MSR_IA32_PL3_SSP			0x000006A7U
#define MSR_IA32_LSTAR				0xC0000082U

#define MAX_SSDT_ENTRIES 4096

#define GDI_HANDLE_BUFFER_SIZE 34

typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef unsigned long DWORD;

// Structs
struct _CONTROL_AREA;
struct _ACTIVATION_CONTEXT;

typedef struct _THREAD_WORK_ITEM {
    HANDLE ThreadId;
    PKTHREAD KThread;
} THREAD_WORK_ITEM, * PTHREAD_WORK_ITEM;

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO {
    OBJECT_NAME_INFORMATION* ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO, * PSE_AUDIT_PROCESS_CREATION_INFO;

typedef struct _SECTION_IMAGE_INFORMATION
{
    PVOID TransferAddress;
    ULONG ZeroBits;
    ULONG MaximumStackSize;
    ULONG CommittedStackSize;
    ULONG SubSystemType;
    union
    {
        struct
        {
            WORD SubSystemMinorVersion;
            WORD SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    ULONG GpValue;
    WORD ImageCharacteristics;
    WORD DllCharacteristics;
    WORD Machine;
    UCHAR ImageContainsCode;
    UCHAR ImageFlags;
    ULONG ComPlusNativeReady : 1;
    ULONG ComPlusILOnly : 1;
    ULONG ImageDynamicallyRelocated : 1;
    ULONG Reserved : 5;
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

typedef struct _MI_EXTRA_IMAGE_INFORMATION
{
    ULONG SizeOfHeaders;
} MI_EXTRA_IMAGE_INFORMATION, * PMI_EXTRA_IMAGE_INFORMATION;

typedef struct _MI_SECTION_IMAGE_INFORMATION
{
    SECTION_IMAGE_INFORMATION ExportedImageInformation;
    MI_EXTRA_IMAGE_INFORMATION InternalImageInformation;
} MI_SECTION_IMAGE_INFORMATION, * PMI_SECTION_IMAGE_INFORMATION;

typedef struct _SEGMENT_FLAGS {
    unsigned long TotalNumberOfPtes4132 : 10;
    unsigned long Spare0 : 1;
    unsigned long SessionDriverProtos : 1;
    unsigned long LargePages : 1;
    unsigned long DebugSymbolsLoaded : 1;
    unsigned long WriteCombined : 1;
    unsigned long NoCache : 1;
    unsigned short Short0;
    unsigned long Spare : 1;
    unsigned long DefaultProtectionMask : 5;
    unsigned long Binary32 : 1;
    unsigned long ContainsDebug : 1;
    unsigned char UChar1;
    unsigned long ForceCollision : 1;
    unsigned long ImageSigningType : 3;
    unsigned long ImageSigningLevel : 4;
    unsigned char UChar2;
} SEGMENT_FLAGS, * PSEGMENT_FLAGS;

typedef struct _MMEXTEND_INFO {
    ULONGLONG CommittedSize;
    ULONG ReferenceCount;
} MMEXTEND_INFO, * PMMEXTEND_INFO;

typedef struct _SEGMENT {
    _CONTROL_AREA* ControlArea;
    ULONG TotalNumberOfPtes;
    SEGMENT_FLAGS SegmentFlags;
    ULONGLONG NumberOfCommittedPages;
    ULONGLONG SizeOfSegment;
    union {
        PMMEXTEND_INFO ExtendInfo;
        PVOID BasedAddress;
    };
    EX_PUSH_LOCK SegmentLock;
    union {
        ULONGLONG ImageCommitment;
        ULONG CreatingProcessId;
    } u1;
    union {
        PMI_SECTION_IMAGE_INFORMATION ImageInformation;
        PVOID FirstMappedVa;
    } u2;
    PVOID PrototypePte;
} SEGMENT, * PSEGMENT;

typedef struct _MMVAD_FLAGS {
    ULONG Lock : 1;
    ULONG LockContended : 1;
    ULONG DeleteInProgress : 1;
    ULONG NoChange : 1;
    ULONG VadType : 3;
    ULONG Protection : 5;
    ULONG PreferredNode : 6;
    ULONG PageSize : 2;
    ULONG PrivateMemory : 1;
    //ULONG Spare : 11;
} MMVAD_FLAGS, * PMMVAD_FLAGS;

struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONG Locked : 1;
            ULONG Waiting : 1;
            ULONG Waking : 1;
            ULONG MultipleShared : 1;
            ULONG Shared : 28;
        };
        ULONG Value;
        VOID* Ptr;
    };
};

struct _EX_FAST_REF
{
    union
    {
        VOID* Object;
        ULONGLONG RefCnt : 4;
        ULONGLONG Value;
    };
};

typedef struct _RTL_AVL_TREE
{
    PRTL_BALANCED_NODE BalancedRoot;
    PVOID OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    ULONG DepthOfTree;
} RTL_AVL_TREE, * PRTL_AVL_TREE;

typedef struct _MMADDRESS_NODE
{
    union
    {
        LONG Balance : 2;
        struct _MMADDRESS_NODE* Parent;
    } u1;
    struct _MMADDRESS_NODE* LeftChild;
    struct _MMADDRESS_NODE* RightChild;
    ULONG StartingVpn;
    ULONG EndingVpn;
} *PMMADDRESS_NODE, MMADDRESS_NODE;

typedef struct _MM_AVL_TABLE
{
    _MMADDRESS_NODE BalancedRoot;
    ULONG DepthOfTree : 5;
    ULONG Unused : 3;
    ULONG NumberGenericTableElements : 24;
    PVOID NodeHint;
    PVOID NodeFreeHint;
} MM_AVL_TABLE, * PMM_AVL_TABLE;

struct _MMVAD_FLAGS2
{
    ULONG FileOffset : 24;
    ULONG SecNoChange : 1;
    ULONG OneSecured : 1;
    ULONG MultipleSecured : 1;
    ULONG Spare : 1;
    ULONG LongVad : 1;
    ULONG ExtendableFile : 1;
    ULONG Inherit : 1;
    ULONG CopyOnWrite : 1;
};

typedef struct _MMVAD
{
    union
    {
        LONG Balance : 2;
        struct _MMVAD* Parent;
    } u1;
    struct _MMVAD* LeftChild;
    struct _MMVAD* RightChild;
    ULONG StartingVpn;
    ULONG EndingVpn;
    union
    {
        ULONG LongFlags;
        struct _MMVAD_FLAGS VadFlags;
    } u;
    struct _CONTROL_AREA* ControlArea;
    struct _MMPTE* FirstPrototypePte;
    struct _MMPTE* LastContiguousPte;
    union
    {
        ULONG LongFlags2;
        struct _MMVAD_FLAGS2 VadFlags2;
    } u2;
} *PMMVAD, MMVAD;

typedef struct _MMSECTION_FLAGS
{
    ULONG BeingDeleted : 1;
    ULONG BeingCreated : 1;
    ULONG BeingPurged : 1;
    ULONG NoModifiedWriting : 1;
    ULONG FailAllIo : 1;
    ULONG Image : 1;
    ULONG Based : 1;
    ULONG File : 1;
    ULONG Networked : 1;
    ULONG Rom : 1;
    ULONG PhysicalMemory : 1;
    ULONG CopyOnWrite : 1;
    ULONG Reserve : 1;
    ULONG Commit : 1;
    ULONG Accessed : 1;
    ULONG WasPurged : 1;
    ULONG UserReference : 1;
    ULONG GlobalMemory : 1;
    ULONG DeleteOnClose : 1;
    ULONG FilePointerNull : 1;
    ULONG GlobalOnlyPerSession : 1;
    ULONG SetMappedFileIoComplete : 1;
    ULONG CollidedFlush : 1;
    ULONG NoChange : 1;
    ULONG Spare : 1;
    ULONG UserWritable : 1;
    ULONG PreferredNode : 6;
} MMSECTION_FLAGS, * PMMSECTION_FLAGS;

typedef struct _CONTROL_AREA
{
    struct _SEGMENT* Segment;
    union
    {
        struct _LIST_ENTRY ListHead;
        VOID* AweContext;
    };
    ULONG NumberOfSectionReferences;
    ULONG NumberOfPfnReferences;
    ULONG NumberOfMappedViews;
    ULONG NumberOfUserReferences;
    union
    {
        ULONG LongFlags;
        struct _MMSECTION_FLAGS Flags;
    } u;
    struct _EX_FAST_REF FilePointer;
    volatile LONG ControlAreaLock;
    ULONG ModifiedWriteCount;
    struct _MI_CONTROL_AREA_WAIT_BLOCK* WaitList;
    union
    {
        struct
        {
            union
            {
                ULONG NumberOfSystemCacheViews;
                ULONG ImageRelocationStartBit;
            };
            union
            {
                volatile LONG WritableUserReferences;
                struct
                {
                    ULONG ImageRelocationSizeIn64k : 16;
                    ULONG SystemImage : 1;
                    ULONG CantMove : 1;
                    ULONG StrongCode : 2;
                    ULONG BitMap : 2;
                    ULONG ImageActive : 1;
                    ULONG ImageBaseOkToReuse : 1;
                };
            };
            union
            {
                ULONG FlushInProgressCount;
                ULONG NumberOfSubsections;
                struct _MI_IMAGE_SECURITY_REFERENCE* SeImageStub;
            };
        } e2;
    } u2;
    struct _EX_PUSH_LOCK FileObjectLock;
    volatile ULONGLONG LockedPages;
    union
    {
        ULONG IoAttributionContext : 29;
        ULONG Spare : 3;
        ULONG ImageCrossPartitionCharge;
        ULONG CommittedPageCount : 20;
    } u3;
} CONTROL_AREA, * PCONTROL_AREA;

typedef struct _SUBSECTION
{
    struct _CONTROL_AREA* ControlArea;
    struct _MMPTE* SubsectionBase;
    struct _SUBSECTION* NextSubsection;
    ULONG PtesInSubsection;
    union
    {
        ULONG UnusedPtes;
        struct _MM_AVL_TABLE* GlobalPerSessionHead;
    };
    union
    {
        ULONG LongFlags;
        VOID* SubsectionFlags;
    } u;
    ULONG StartingSector;
    ULONG NumberOfFullSectors;
} SUBSECTION, * PSUBSECTION;

typedef struct _PEB_LDR_DATA {
    BYTE                          Reserved1[8];
    PVOID                         Reserved2[3];
    LIST_ENTRY                    InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE                          Reserved1[16];
    PVOID                         Reserved2[10];
    UNICODE_STRING                ImagePathName;
    UNICODE_STRING                CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;

union _KWAIT_STATUS_REGISTER
{
    UCHAR Flags;
    UCHAR State : 3;
    UCHAR Affinity : 1;
    UCHAR Priority : 1;
    UCHAR Apc : 1;
    UCHAR UserApc : 1;
    UCHAR Alert : 1;
};

typedef struct _PS_PROTECTION {
    UCHAR Level;
    struct {
        UCHAR Type : 3;
        UCHAR Audit : 1;
        UCHAR Signer : 4;
    };
} PS_PROTECTION, * PPS_PROTECTION;

//typedef struct _FUNCTION_MAP_ENTRY {
//    PVOID FunctionAddress;
//    UNICODE_STRING FunctionName;
//    struct _FUNCTION_MAP_ENTRY* Next;
//} FUNCTION_MAP_ENTRY, * PFUNCTION_MAP_ENTRY;
//
//typedef struct _FUNCTION_MAP {
//    PFUNCTION_MAP_ENTRY Head;
//    KSPIN_LOCK Lock;
//} FUNCTION_MAP, * PFUNCTION_MAP;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
    PULONG ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG NumberOfServices;
    PUCHAR ParamTableBase;
} SERVICE_DESCRIPTOR_TABLE, * PSERVICE_DESCRIPTOR_TABLE;

typedef struct _THREAD_TRACKER_ENTRY {
    HANDLE ProcessId;
    HANDLE ThreadId;
    BOOLEAN IsCreated;
    LIST_ENTRY ListEntry;
} THREAD_TRACKER_ENTRY, * PTHREAD_TRACKER_ENTRY;

typedef struct _THREAD_TRACKER {
    LIST_ENTRY Head;
    KSPIN_LOCK Lock;
} THREAD_TRACKER, * PTHREAD_TRACKER;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _FUNCTION_NODE {
    PVOID Address;
    UNICODE_STRING FunctionName;
    struct _FUNCTION_NODE* Next;
} FUNCTION_NODE, * PFUNCTION_NODE;

#define HASH_TABLE_SIZE 256

typedef struct _FUNCTION_MAP {
    PFUNCTION_NODE Buckets[HASH_TABLE_SIZE];
} FUNCTION_MAP, * PFUNCTION_MAP;

typedef struct _SSDT_ENTRY {
    ULONG SSN;              
    PVOID FunctionAddress;  
} SSDT_ENTRY, * PSSDT_ENTRY;

typedef struct _SSDT_TABLE {
    ULONG NumberOfEntries;  
    SSDT_ENTRY* Entries;    
} SSDT_TABLE, * PSSDT_TABLE;

//struct _GDI_HANDLE_BUFFER;
#define GDI_HANDLE_BUFFER_SIZE 34
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _PEB2 {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    ULONG CrossProcessFlags;
    PVOID KernelCallbackTable;
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;
    SIZE_T MinimumStackCommit;
} PEB2, * PPEB2;
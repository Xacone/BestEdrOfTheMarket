#include "Globals.h"

BOOLEAN isCpuVTxEptSupported() {

    int cpuInfo[4] = { 0 };

    __cpuid(cpuInfo, 1);
    bool vtxSupported = (cpuInfo[2] & (1 << 5)) != 0;

    __cpuid(cpuInfo, 0x80000001);
    bool eptSupported = (cpuInfo[2] & (1 << 26)) != 0;
    
    if (vtxSupported || eptSupported) {
        return TRUE;
    }

    return FALSE;
}

int contains_bytes_bitwise(UINT64 address, const UINT8* bytes, size_t num_bytes) {

    for (int i = 0; i < 8; ++i) {
        UINT8 current_byte = (address >> (i * 8)) & 0xFF;

        for (size_t j = 0; j < num_bytes; ++j) {
            if (current_byte == bytes[j]) {
                return 1;
            }
        }
    }
    return 0;
}

int contains_signature(ULONGLONG address, size_t memory_size, const UINT8* signature, size_t signature_size) {

    const UINT8* memory = (const UINT8*)address;

    if (signature_size > memory_size) {
        return 0;
    }

    for (size_t i = 0; i <= memory_size - signature_size; ++i) {
        int match = 1;
        for (size_t j = 0; j < signature_size; ++j) {
            if (memory[i + j] != signature[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            return 1;
        }
    }

    return 0;
}

int starts_with_signature(ULONGLONG address, const UINT8* signature, size_t signature_size) {
    const UINT8* memory = (const UINT8*)address;

    for (size_t i = 0; i < signature_size; ++i) {
        if (memory[i] != signature[i]) {
            return 0;
        }
    }

    return 1;
}

ULONG64 NullifyLastDigit(ULONG64 address) {
    return (ULONG64)(address & 0xFFFFFFFFFFFFFFF0);
}

ULONG64 GetUserModeAddressVpn(ULONG64 address) {
    return (ULONG64)((address & 0xFFFF0FFFFFFFFFFF) >> 12);
}

ULONG64 GetWow64UserModeAddressVpn(ULONG64 address) {
    return (ULONG64)(address >> 12);
}

BOOLEAN FileIsExe(PUNICODE_STRING UnicodeString) {

    if (UnicodeString == NULL || UnicodeString->Buffer == NULL) {
        return FALSE;
    }

    USHORT unicodeStringLengthInChars = UnicodeString->Length / sizeof(WCHAR);

    if (unicodeStringLengthInChars < 4) {
        return FALSE;
    }

    WCHAR* end = &UnicodeString->Buffer[unicodeStringLengthInChars - 4];
    if (wcsncmp(end, L".exe", 4) == 0) {
        return TRUE;
    }

    return FALSE;
}

BOOLEAN UnicodeStringContains(PUNICODE_STRING UnicodeString, PCWSTR SearchString) {

    if (UnicodeString == NULL || UnicodeString->Buffer == NULL || SearchString == NULL) {
        return FALSE;
    }

    size_t searchStringLength = wcslen(SearchString);
    if (searchStringLength == 0) {
        return FALSE;
    }

    USHORT unicodeStringLengthInChars = UnicodeString->Length / sizeof(WCHAR);

    if (unicodeStringLengthInChars < searchStringLength) {
        return FALSE;
    }

    for (USHORT i = 0; i <= unicodeStringLengthInChars - searchStringLength; i++) {

        if (!MmIsAddressValid(&UnicodeString->Buffer[i])) {
            return FALSE;
        }

        if (wcsncmp(&UnicodeString->Buffer[i], SearchString, searchStringLength) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

const char* GetProtectionTypeString(UCHAR type) {
    switch (type) {
    case 0x0: return "None";
    case 0x1: return "Light Protection";
    case 0x2: return "Medium Protection";
    case 0x3: return "High Protection";
    default: return "Unknown";
    }
}

const char* GetSignerTypeString(UCHAR signer) {
    switch (signer) {
    case 0x0: return "None";
    case 0x1: return "Signed by Microsoft";
    case 0x2: return "Signed by Windows Store";
    case 0x3: return "Signed by System";
    case 0x4: return "Signed by User";
    case 0x5: return "Signed by Trusted Developer";
    default: return "Unknown";
    }
}

const char* GetProtectionString(ULONG protection)
{

    switch (protection)
    {
    case MM_ZERO_ACCESS:
        return "NO ACCESS";
    case MM_READONLY:
        return "READ-ONLY";
    case MM_EXECUTE:
        return "EXECUTE-ONLY";
    case MM_EXECUTE_READ:
        return "EXECUTE AND READ";
    case MM_READWRITE:
        return "READ AND WRITE";
    case MM_WRITECOPY:
        return "WRITE COPY";
    case MM_EXECUTE_READWRITE:
        return "EXECUTE, READ, AND WRITE";
    case MM_EXECUTE_WRITECOPY:
        return "EXECUTE AND WRITE COPY";
    case MM_NOACCESS:
        return "NO ACCESS (USED FOR SPECIFIC REASONS)";
    case MM_GUARD_PAGE:
        return "GUARD PAGE (USED FOR STACK OVERFLOW PROTECTION)";
    case MM_NOCACHE:
        return "NO CACHING";
    case MM_WRITECOMBINE:
        return "WRITE COMBINING (USED FOR DEVICES)";
    case MM_EXECUTE_NOCACHE:
        return "EXECUTE WITHOUT CACHING";
    case MM_EXECUTE_WRITECOMBINE:
        return "EXECUTE WITH WRITE COMBINING";
    case MM_EXECUTE_GUARD_PAGE:
        return "EXECUTE WITH GUARD PAGE";
    case MM_EXECUTE_NOACCESS:
        return "EXECUTE WITHOUT ACCESS (USED FOR SPECIFIC REASONS)";
    default:
        return "UNKNOWN PROTECTION";
    }
}

NTSTATUS TerminateProcess(HANDLE ProcessId) {

    PEPROCESS Process;
    NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);

    if (NT_SUCCESS(Status)) {

        HANDLE ProcessHandle;

        Status = ObOpenObjectByPointer(
            Process,
            OBJ_KERNEL_HANDLE,
            NULL,
            PROCESS_TERMINATE,
            *PsProcessType,
            KernelMode,
            &ProcessHandle
        );

        if (NT_SUCCESS(Status)) {
            Status = ZwTerminateProcess(ProcessHandle, 0);
            ZwClose(ProcessHandle);
        }

        ObDereferenceObject(Process);
    }
    return Status;
}

char* FetchNtVersion(DWORD buildNumber) {

    switch (buildNumber)
    {
        case 10240: return "Windows 10 Version 1507";
        case 10586: return "Windows 10 Version 1511";
        case 14393: return "Windows 10 Version 1607";
        case 15063: return "Windows 10 Version 1703";
        case 16299: return "Windows 10 Version 1709";
        case 17134: return "Windows 10 Version 1803";
        case 17763: return "Windows 10 Version 1809";
        case 18362: return "Windows 10 Version 1903";
        case 18363: return "Windows 10 Version 1909";
        case 19041: return "Windows 10 Version 2004";
        case 19042: return "Windows 10 Version 20H2";
        case 19043: return "Windows 10 Version 21H1";
        case 19044: return "Windows 10 Version 21H2";
        case 19045: return "Windows 10 Version 22H2";
        case 20348: return "Windows Server 2022";
        case 22000: return "Windows 11 Version 21H2";
        case 22621: return "Windows 11 Version 22H2";
        case 22631: return "Windows 11 Version 23H2";
        case 25000: return "Windows Server 23H2";
        case 26000: return "Windows 11 Version 24H2";
        default: return "Unknown Windows Version";
    }
}


NTSTATUS getProcessBaseAddr(HANDLE procId, PVOID* baseAddr, PSIZE_T size) {

    PEPROCESS process;
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION processInfo;
    ULONG returnLength;

    status = PsLookupProcessByProcessId(procId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &processInfo, sizeof(processInfo), &returnLength);

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(process);
        return status;
    }

    __try {

        *baseAddr = ((PPEB2)processInfo.PebBaseAddress)->ImageBaseAddress;

        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS64 ntHeader;

        RtlCopyMemory(&dosHeader, *baseAddr, sizeof(IMAGE_DOS_HEADER));
        RtlCopyMemory(&ntHeader, (PVOID)((ULONG64)*baseAddr + dosHeader.e_lfanew), sizeof(IMAGE_NT_HEADERS64));

        *size = ntHeader.OptionalHeader.SizeOfImage;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        ObDereferenceObject(process);
        return status;
    }

    return STATUS_SUCCESS;
}

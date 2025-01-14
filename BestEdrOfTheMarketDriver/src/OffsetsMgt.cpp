#include "Globals.h"

KERNEL_STRUCTURES_OFFSET* OffsetsMgt::offsets = NULL;

BOOLEAN OffsetsMgt::InitWinStructsOffsets() {

	offsets = (PKERNEL_STRUCTURES_OFFSET)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KERNEL_STRUCTURES_OFFSET), 'offs');

    if (!offsets) {
		DbgPrint("[-] ExAllocatePool2 failed for offsets\n");
		return FALSE;
    }

    RTL_OSVERSIONINFOW versionInfo = { 0 };
	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    RtlGetVersion(&versionInfo);

    switch (versionInfo.dwBuildNumber) {

    // Win 10

    case 19041: {

        offsets->ActiveProcessLinks = 0x448;
        offsets->SeAuditProcessCreationInfo = 0x5c0;
        offsets->ThreadListHead = 0x5e0;
        offsets->VadRoot = 0x7d8;
        offsets->Flags3 = 0x87c;
        offsets->MitigationFlags2Values = 0x9d4;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x4e8;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 19042: {

        offsets->ActiveProcessLinks = 0x448;
        offsets->SeAuditProcessCreationInfo = 0x5c0;
        offsets->ThreadListHead = 0x5e0;
        offsets->VadRoot = 0x7d8;
        offsets->Flags3 = 0x87c;
        offsets->MitigationFlags2Values = 0x9d4;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x4e8;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 19043: {

        offsets->ActiveProcessLinks = 0x448;
        offsets->SeAuditProcessCreationInfo = 0x5c0;
        offsets->ThreadListHead = 0x5e0;
        offsets->VadRoot = 0x7d8;
        offsets->Flags3 = 0x87c;
        offsets->MitigationFlags2Values = 0x9d4;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x4e8;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 19044: {

        offsets->ActiveProcessLinks = 0x448;
        offsets->SeAuditProcessCreationInfo = 0x5c0;
        offsets->ThreadListHead = 0x5e0;
        offsets->VadRoot = 0x7d8;
        offsets->Flags3 = 0x87c;
        offsets->MitigationFlags2Values = 0x9d4;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x4e8;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 19045: {

        offsets->ActiveProcessLinks = 0x448;
        offsets->SeAuditProcessCreationInfo = 0x5c0;
        offsets->ThreadListHead = 0x5e0;
        offsets->VadRoot = 0x7d8;
        offsets->Flags3 = 0x87c;
        offsets->MitigationFlags2Values = 0x9d4;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x4e8;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    // Win 11 

    case 22000: {

        offsets->ActiveProcessLinks = 0x448;
        offsets->SeAuditProcessCreationInfo = 0x5c0;
        offsets->ThreadListHead = 0x5e0;
        offsets->VadRoot = 0x7d8;
        offsets->Flags3 = 0x87c;
        offsets->MitigationFlags2Values = 0x9d4;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x538;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 22631: {

        offsets->ActiveProcessLinks = 0x448;
        offsets->SeAuditProcessCreationInfo = 0x5c0;
        offsets->ThreadListHead = 0x5e0;
        offsets->VadRoot = 0x7d8;
        offsets->Flags3 = 0x87c;
        offsets->MitigationFlags2Values = 0x9d4;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x538;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 22632: {

        offsets->ActiveProcessLinks = 0x448;
        offsets->SeAuditProcessCreationInfo = 0x5c0;
        offsets->ThreadListHead = 0x5e0;
        offsets->VadRoot = 0x7d8;
        offsets->Flags3 = 0x87c;
        offsets->MitigationFlags2Values = 0x9d4;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x538;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    default: {
    }
		DbgPrint("[-] Unsupported Windows version: %d\n", versionInfo.dwBuildNumber);
        return FALSE;
    }

    return TRUE;
}
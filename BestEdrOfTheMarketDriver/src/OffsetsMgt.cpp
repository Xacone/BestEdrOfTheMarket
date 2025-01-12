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

    case 10240: {

        offsets->ActiveProcessLinks = 0x2f0;
        offsets->SeAuditProcessCreationInfo = 0x460;
        offsets->ThreadListHead = 0x480;
        offsets->VadRoot = 0x608;
        offsets->Flags3 = 0x6ac;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x690;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 10586: {

        offsets->ActiveProcessLinks = 0x2f0;
        offsets->SeAuditProcessCreationInfo = 0x468;
        offsets->ThreadListHead = 0x488;
        offsets->VadRoot = 0x610;
        offsets->Flags3 = 0x6b4;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x690;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 14393: {

        offsets->ActiveProcessLinks = 0x2f0;
        offsets->SeAuditProcessCreationInfo = 0x468;
        offsets->ThreadListHead = 0x488;
        offsets->VadRoot = 0x620;
        offsets->Flags3 = 0x6c4;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x698;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 15063: {

        offsets->ActiveProcessLinks = 0x2e8;
        offsets->SeAuditProcessCreationInfo = 0x468;
        offsets->ThreadListHead = 0x488;
        offsets->VadRoot = 0x628;
        offsets->Flags3 = 0x6cc;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x6a0;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 16299: {

        offsets->ActiveProcessLinks = 0x2e8;
        offsets->SeAuditProcessCreationInfo = 0x468;
        offsets->ThreadListHead = 0x488;
        offsets->VadRoot = 0x628;
        offsets->Flags3 = 0x6cc;
        offsets->MitigationFlags2Values = 0x82c;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x6a8;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 17134: {

        offsets->ActiveProcessLinks = 0x2e8;
        offsets->SeAuditProcessCreationInfo = 0x468;
        offsets->ThreadListHead = 0x488;
        offsets->VadRoot = 0x628;
        offsets->Flags3 = 0x6cc;
        offsets->MitigationFlags2Values = 0x82c;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x6a8;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 17763: {

        offsets->ActiveProcessLinks = 0x2e8;
        offsets->SeAuditProcessCreationInfo = 0x468;
        offsets->ThreadListHead = 0x488;
        offsets->VadRoot = 0x628;
        offsets->Flags3 = 0x6cc;
        offsets->MitigationFlags2Values = 0x824;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x6a8;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 18362: {

        offsets->ActiveProcessLinks = 0x2f0;
        offsets->SeAuditProcessCreationInfo = 0x468;
        offsets->ThreadListHead = 0x488;
        offsets->VadRoot = 0x658;
        offsets->Flags3 = 0x6fc;
        offsets->MitigationFlags2Values = 0x854;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x6b8;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

    case 18363: {

        offsets->ActiveProcessLinks = 0x2f0;
        offsets->SeAuditProcessCreationInfo = 0x468;
        offsets->ThreadListHead = 0x488;
        offsets->VadRoot = 0x658;
        offsets->Flags3 = 0x6fc;
        offsets->MitigationFlags2Values = 0x854;
        offsets->Subsection = 0x48;
        offsets->Segment = 0x0;
        offsets->FilePointer = 0x40;
        offsets->ThreadListEntry = 0x6b8;
        offsets->Header = 0x0;
        offsets->TrapFrame = 0x90;
        break;
    }

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
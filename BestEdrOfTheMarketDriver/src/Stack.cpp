#include "Globals.h"

ULONG64 StackUtils::getStackStartRtl() {

	PVOID stackFrames[MAX_STACK_FRAMES];
	ULONG capturedFrames = RtlWalkFrameChain(stackFrames, MAX_STACK_FRAMES, RTL_WALK_USER_MODE_STACK);

	if (capturedFrames > 0) {
		PVOID firstFrame = stackFrames[capturedFrames - 1];
		return (ULONG64)firstFrame;
	}

	return NULL;
}

ULONG64 StackUtils::getSSP() {

	__try {
		return __readmsr(MSR_IA32_PL3_SSP);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return NULL;
	}
}

BOOLEAN StackUtils::isCETEnabled() {

	ULONG64 cr4 = __readcr4();

	return (cr4 & (1 << 23)) != 0;
}

BOOLEAN StackUtils::isCETSupported() {

	int cpuInfo[4] = { 0 };

	__cpuidex(cpuInfo, 0x7, 0x0);

	if (!(cpuInfo[1] & (1 << 11))) {
		return FALSE;
	}

	if (!(cpuInfo[2] & (1 << 23))) {
		return FALSE;
	}

	return TRUE;
}



BOOLEAN StackUtils::isStackCorruptedRtlCET(
    PVOID* SpoofedAddr
) {
    NTSTATUS status;
    PPS_PROTECTION curProcProtection = PsGetProcessProtection(PsGetCurrentProcess());

    if (curProcProtection->Level != 0x0) {
        return FALSE;
    }

    HANDLE parentCid = PsGetProcessInheritedFromUniqueProcessId(PsGetCurrentProcess());
    PEPROCESS parentProc;

    status = PsLookupProcessByProcessId(parentCid, &parentProc);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    PPS_PROTECTION parentProcProtection = PsGetProcessProtection(parentProc);

    if ((DWORD_PTR)parentProcProtection > (BYTE)0x0) {
        return FALSE;
    }

    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

    __try {
        PVOID ssp = (PVOID)this->getSSP();

        if (ssp == nullptr || ssp == 0x0) {
            KeLowerIrql(oldIrql);
            return FALSE;
        }

        PVOID stackFrames[MAX_STACK_FRAMES] = { 0 };
        ULONG capturedFramesCount = RtlWalkFrameChain(stackFrames, MAX_STACK_FRAMES, RTL_WALK_USER_MODE_STACK);

        if (capturedFramesCount == 0) {
            KeLowerIrql(oldIrql);
            return FALSE;
        }

        PVOID shadowStackFrames[MAX_STACK_FRAMES] = { 0 };
        ULONG shadowStackFramesCount = 0;

        DWORD_PTR actual = (DWORD_PTR)ssp;
        DWORD_PTR lastShadowFrame = NULL;

        if (!MmIsAddressValid((PVOID)actual)) {
            KeLowerIrql(oldIrql);
            return FALSE;
        }

        while (shadowStackFramesCount < MAX_STACK_FRAMES) {
            __try {
                if (!MmIsAddressValid((PVOID)actual)) {
                    break;
                }

                PVOID frame = *(PVOID*)actual;
                if (frame == nullptr) {
                    break;
                }

                lastShadowFrame = (DWORD_PTR)(*(PVOID*)actual);
                shadowStackFrames[shadowStackFramesCount] = frame;
                shadowStackFramesCount += 1;
                actual += sizeof(PVOID);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[-] Exception while traversing shadow stack.\n");
                break;
            }
        }

        PVOID capturedStackFramesUser[MAX_STACK_FRAMES] = { 0 };

        for (ULONG i = 0; i < capturedFramesCount; i++) {
            if ((((ULONG64)stackFrames[i]) & (ULONG64)0xFFFF000000000000) != 0xffff000000000000) {
                capturedStackFramesUser[i] = stackFrames[i];
            }
        }

        if (shadowStackFramesCount > 0 && capturedFramesCount > 0) {
            for (ULONG i = 1; i < shadowStackFramesCount; i++) {
                PVOID frame = capturedStackFramesUser[i];
                PVOID shadowFrame = shadowStackFrames[i - 1];

                if (frame == nullptr && shadowFrame == nullptr) {
                    break;
                }

                if (frame == nullptr) {
                    break;
                }

                if ((ULONG64)frame != (ULONG64)shadowFrame) {
                    if (frame == 0x0000000000000000) {
                        PRTL_AVL_TREE root = (PRTL_AVL_TREE)((PUCHAR)PsGetCurrentProcess() + OffsetsMgt::GetOffsets()->VadRoot);

                        BOOLEAN isAddressOutOfSys32Ntdll = FALSE;
                        BOOLEAN isAddressOutOfWow64Ntdll = FALSE;
                        BOOLEAN isWow64 = FALSE;

                        if (PsGetProcessWow64Process(PsGetCurrentProcess()) != NULL) {
                            isWow64 = TRUE;
                        }

                        VadUtils::isAddressOutOfNtdll(
                            (PRTL_BALANCED_NODE)root,
                            (ULONG64)shadowFrame,
                            &isWow64,
                            &isAddressOutOfSys32Ntdll,
                            &isAddressOutOfWow64Ntdll
                        );

                        if (isWow64) {
                            if (isAddressOutOfSys32Ntdll ^ isAddressOutOfWow64Ntdll) {
                                *SpoofedAddr = shadowFrame;
                                KeLowerIrql(oldIrql);
                                return TRUE;
                            }
                            else {
                                *SpoofedAddr = shadowFrame;
                                KeLowerIrql(oldIrql);
                                return isAddressOutOfSys32Ntdll;
                            }
                        }
                    }
                    else {
                        *SpoofedAddr = shadowFrame;
                        KeLowerIrql(oldIrql);
                        return TRUE;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[-] General exception caught in isStackCorruptedRtlCET.\n");
        KeLowerIrql(oldIrql);
        return FALSE;
    }

    KeLowerIrql(oldIrql);
    return FALSE;
}

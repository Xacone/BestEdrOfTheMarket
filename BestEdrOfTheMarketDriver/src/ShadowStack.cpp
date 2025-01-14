#include "Globals.h"
//
//BOOLEAN ShadowStackUtils::checkForStackCorruptionShadow()
//{
//
//	PVOID ssp = (PVOID)__readmsr(MSR_IA32_PL3_SSP);
//
//	PVOID stackFrames[MAX_STACK_FRAMES];
//	ULONG framesCaptured = RtlWalkFrameChain(stackFrames, MAX_STACK_FRAMES, RTL_WALK_USER_MODE_STACK);
//	PVOID shadowStackFrames[MAX_STACK_FRAMES];
//	ULONG shadowStackFramesCount = 0;
//
//	if ((ssp != 0x0) && (ssp != NULL)) {
//
//		DWORD_PTR lastFrame = NULL;
//		DWORD_PTR actual = (DWORD_PTR)ssp;
//
//		if (MmIsAddressValid((PVOID)actual)) {
//
//			do {
//				__try {
//
//					if (*(PVOID*)actual == NULL) {
//						break;
//					}
//
//					lastFrame = (DWORD_PTR)(*(PVOID*)actual);
//					shadowStackFrames[shadowStackFramesCount] = (PVOID)(*(PVOID*)actual);
//					shadowStackFramesCount += 1;
//					actual += sizeof(PVOID);
//
//				}
//				__except (EXCEPTION_EXECUTE_HANDLER) {
//
//					DbgPrint("[-] Exception\n");
//					break;
//				}
//
//			} while (MmIsAddressValid((PVOID)actual));
//
//			if (framesCaptured > 0) {
//
//				if ((DWORD_PTR)(stackFrames[framesCaptured - 1]) != (DWORD_PTR)lastFrame) {
//					return TRUE;
//				}
//			}
//
//		}
//	}
//
//	return FALSE;
//}
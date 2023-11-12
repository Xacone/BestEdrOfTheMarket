#pragma once

#include "ErrorsReportingUtils.h"

void hookIatTableEntry(HANDLE hProc, PVOID origin, PVOID target) {

	PVOID toOverwrite = origin;
	DWORD oldProtect = 0;
	SIZE_T bytesWritten;

	if (!VirtualProtectEx(hProc, origin, 8, PAGE_READWRITE, &oldProtect)) {
		exit(-21);
	}

	if (!WriteProcessMemory(hProc, origin, (PVOID)target, 8, &bytesWritten)) {
		printLastError();
		exit(-22);
	}

	if (!VirtualProtectEx(hProc, origin, 8, oldProtect, &oldProtect)) {
		exit(-23);
	}
}

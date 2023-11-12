#pragma once
#include <Windows.h>
#include <iostream>
#include <ntstatus.h>

#include "ErrorsReportingUtils.h"

typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory) (
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesWritten
	);

pNtWriteVirtualMemory NtWriteVirtualMemory = nullptr;

DWORD doingSomethingWithTheSyscall(HANDLE hProc, DWORD_PTR funcAddr) {

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

	DWORD oldProtect = NULL;
	BYTE ssn[1] = { 0x21 };
	PSIZE_T bytesWritten = nullptr;

	if (VirtualProtectEx(hProc, (LPVOID)(funcAddr + 0x4), sizeof(ssn), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		NTSTATUS status = NtWriteVirtualMemory(
			hProc,
			(LPVOID)(funcAddr + 0x4),
			ssn,
			sizeof(ssn),
			bytesWritten);
		if (status == STATUS_SUCCESS) {
			if (VirtualProtectEx(hProc, (LPVOID)(funcAddr + 0x4), sizeof(ssn), oldProtect, &oldProtect)) {
			}
		}
	}
	return NULL;
}
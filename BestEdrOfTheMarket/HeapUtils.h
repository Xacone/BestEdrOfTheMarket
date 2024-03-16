#pragma once*
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <winternl.h>

#include "ErrorsReportingUtils.h"

class HeapUtils;


// https://stackoverflow.com/questions/3313581/runtime-process-memory-patching-for-restoring-state/3313700#3313700


class HeapUtils {

private:

    PVOID heapAddress = NULL;
    unsigned long usage;
    PEB* peb;
    HANDLE target = NULL;
    unsigned char* p = NULL;
    MEMORY_BASIC_INFORMATION info;

    DWORD_PTR heapAddresses[1024];
    SIZE_T heapSizes[1024];
    SIZE_T h = 0;

public:

    DWORD_PTR* getHeapAddresses() {
		return heapAddresses;
	}

    SIZE_T* getHeapSizes() {
        return heapSizes;
    }

    SIZE_T getHeapSize(int index) {
		return heapSizes[index];
	}

    DWORD_PTR getHeapAddress(int index) {
        return heapAddresses[index];
    }

    SIZE_T getHeapCount() {
		return h;
	}

    HeapUtils(HANDLE& target) {
        this->target = target;
    }

    ~HeapUtils() {
        delete peb;
    }

    BYTE* getHeapRegionContent(int index) {

        BYTE* buffer = new BYTE[heapSizes[index]];
        SIZE_T bytesRead;

        try {
            if (ReadProcessMemory(target, (LPCVOID)heapAddresses[index], buffer, heapSizes[index], &bytesRead)) {
                if (bytesRead != heapSizes[index]) {
                    std::cout << "ReadProcessMemory() failed: " << GetLastError() << std::endl;
                    printLastError();
                    return NULL;
                }
            }
            return buffer;
        } catch(std::exception& e) {
            std::cout << e.what() << std::endl;
        }
        return NULL;
    }

    void printAllHeapRegionsContent() {

        for (int i = 0; i < h; i++) {
            std::cout << "Heap " << std::dec << (int)i << ": " << std::hex << heapAddresses[i] << " - " << heapAddresses[i] + heapSizes[i] << std::endl;
        }
    }

    void getHeapRegions() {

        clearHeapRegions();

        for (p = NULL;
            VirtualQueryEx(target, p, &info, sizeof(info)) == sizeof(info);
            p += info.RegionSize)
        {
            try {
                if (info.State == MEM_COMMIT && info.Type == MEM_PRIVATE) {
                    //std::cout << "[*] Heap @ : " << std::hex << (DWORD_PTR)info.BaseAddress << std::endl;
                    heapAddresses[h] = (DWORD_PTR)info.BaseAddress;
                    heapSizes[h] = info.RegionSize;
                    h++;    
                }
            }
            catch (std::exception& e) {
                continue;
            }
           
        }
    }   

    void clearHeapRegions() {
        for (int i = 0; i < h; i++) {
			heapAddresses[i] = 0;
			heapSizes[i] = 0;
		}
		h = 0;
	}
};

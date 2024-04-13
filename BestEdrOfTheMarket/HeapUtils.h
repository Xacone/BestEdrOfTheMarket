#pragma once*
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <winternl.h>

#include "ProcessStructUtils.h"
#include "ErrorsReportingUtils.h"

class HeapUtils;


// https://stackoverflow.com/questions/3313581/runtime-process-memory-patching-for-restoring-state/3313700#3313700


class HeapUtils {

private:

    PVOID heapAddress = NULL;
    unsigned long usage;
    PPEB peb;
    HANDLE target = NULL;
    unsigned char* p = NULL;
    MEMORY_BASIC_INFORMATION info;

    PVOID heapAddresses[1024];
    SIZE_T heapSizes[1024];
    SIZE_T h = 0;

public:

    PVOID* getHeapAddresses() {
		return heapAddresses;
	}

    SIZE_T* getHeapRegionSizes() {
        return heapSizes;
    }

    SIZE_T getHeapRegionSize(int index) {
		return heapSizes[index];
	}

    PVOID getHeapAddress(int index) {
        return heapAddresses[index];
    }

    SIZE_T getHeapCount() {
		return h;
	}

    HeapUtils(HANDLE& target) {
        this->target = target;
        peb = getHandledProcessPeb(target);
    }

    ~HeapUtils() {
        //delete peb;
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
            std::cout << "Heap " << std::dec << (int)i << ": " << std::hex << heapAddresses[i] << " - " << (DWORD_PTR)heapAddresses[i] + heapSizes[i] << std::endl;
        }
    }

    // Old method

    //void getHeapRegions() {

    //    clearHeapRegions();

    //    for (p = NULL;
    //        VirtualQueryEx(target, p, &info, sizeof(info)) == sizeof(info);
    //        p += info.RegionSize)
    //    {
    //        try {
    //            if (info.State == MEM_COMMIT && info.Type == MEM_PRIVATE) {
    //                //std::cout << "[*] Heap @ : " << std::hex << (DWORD_PTR)info.BaseAddress << std::endl;
    //                heapAddresses[h] = (DWORD_PTR)info.BaseAddress;
    //                heapSizes[h] = info.RegionSize;
    //                h++;    
    //            }
    //        }
    //        catch (std::exception& e) {
    //            continue;
    //        }
    //       
    //    }
    //}   

    // New method
    // Heap regions + Size
    void retrieveHeapRegions(BOOL verbose) {

         PVOID processHeap;
         ReadProcessMemory(target, (LPCVOID)((DWORD_PTR)peb + 0x30), &processHeap, sizeof(PVOID), NULL);

         DWORD numberOfHeaps;
         ReadProcessMemory(target, (LPCVOID)((DWORD_PTR)peb + 0xE8), &numberOfHeaps, sizeof(DWORD), NULL);

         PVOID* ProcessHeaps;
         ReadProcessMemory(target, (LPCVOID)((DWORD_PTR)peb + 0xF0), &ProcessHeaps, sizeof(PVOID*), NULL);
         
         h = (SIZE_T)numberOfHeaps;

         for (int i = 0; i < numberOfHeaps; i++) {
             PVOID heapAddress;
             ReadProcessMemory(target, (LPCVOID)((DWORD_PTR)ProcessHeaps + i * sizeof(PVOID)), &heapAddress, sizeof(PVOID), NULL);

             heapAddresses[i] = heapAddress;
             if (VirtualQueryEx(target, heapAddress, &info, sizeof(info)) == sizeof(info)) {
                 heapSizes[i] = info.RegionSize;
             }
         }

         std::cout << "\n" << std::endl;

         // print heaps and size
        for (int i = 0; i < numberOfHeaps; i++) {
            if (verbose) {
                std::cout << "[*] Heap " << (i + 1) << " at " << std::hex << heapAddresses[i] << " size: " << std::dec << (int)(heapSizes[i]) / 1000 << " kb" << std::endl;
            }
		}
        
        if (verbose) {
            std::cout << "\n" << std::endl;
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

		
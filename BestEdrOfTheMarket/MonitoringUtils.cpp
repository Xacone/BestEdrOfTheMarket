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
#include <locale>
#include <codecvt>

#include <DbgHelp.h>
#include <Psapi.h>

#include "Pe64Utils.h"
#include "HeapUtils.h"

#include "Startup.h"
#include "ProcessStructUtils.h"
#include "ModuleLoadingUtils.h"
#include "SSNHookingUtils.h"
#include "IATHookingUtils.h"
#include "ColorsUtils.h"
#include "SymbolsUtils.h"
#include "BytesSequencesUtils.h"

#include "IPCUtils.h"

#include "json/json.h"

#pragma comment(lib, "dbghelp.lib")

#pragma warning(disable : 266) // temporary

using namespace std;

#define RIP_RANGE 0x29

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

DWORD64 GetDetailedStackTraceWithReturnAddresses(HANDLE, HANDLE);

bool containsSequence(const BYTE*, size_t, const BYTE*, size_t);
void MonitorPointersToUnbackedAddresses(HANDLE, THREADENTRY32);
bool searchForOccurenceInByteArray(BYTE*, int, BYTE*, int);
void MonitorThreadCallStack(HANDLE, THREADENTRY32);
DWORD_PTR printFunctionsMappingKeys(const char*);
BOOL analyseProcessThreadsStackTrace(HANDLE);
void deleteMonitoringWorkerThreads();
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

// Flagged Patterns from YaroRules.json for stack monitoring 
// int : pattern id
// BYTE* : pattern converted to bytes (see hexStringToByteArray) 
std::unordered_map<int, BYTE*> stackPatterns;

// Flagged Patterns from YaroRules.json for heap monitoring 
// BYTE* : pattern converted to bytes (see hexStringToByteArray) 
// SIZE_T : pattern size
std::unordered_map<BYTE*, SIZE_T> heapPatterns;

// Flagged Patterns from YaroRules.json for dll hooking (a)
// BYTE* : pattern converted to bytes (see hexStringToByteArray) 
// SIZE_T : pattern size
std::unordered_map<BYTE*, SIZE_T> dllPatterns;

// General flagged Patterns from YaroRules.json 
// BYTE* : pattern converted to bytes (see hexStringToByteArray) 
// SIZE_T : pattern size
std::unordered_map<BYTE*, SIZE_T> generalPatterns;

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
		deleteMonitoringWorkerThreads();
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
BOOL _backed_ = FALSE;
BOOL _rop_ = FALSE;
BOOL _debug_ = FALSE;
BOOL _boost_ = FALSE;
BOOL _stack_spoof_ = FALSE;
BOOL _d_syscalls_ = FALSE;
BOOL _i_syscalls_ = FALSE;
BOOL _yara_ = FALSE;

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
		if (!strcmp(argv[arg], "/backed")) { // a degager
			_backed_ = TRUE;
		}
		if (!strcmp(argv[arg], "/rop")) {
			_rop_ = TRUE;
		}	
		if (!strcmp(argv[arg], "/debug")) { 
			_debug_ = TRUE;
		}
		if (!strcmp(argv[arg], "/boost")) { // a degager
			_boost_ = TRUE;
		}
		if (!strcmp(argv[arg], "/stack-spoof")) { // a degager pour l'instant
			_stack_spoof_ = TRUE;
		}
		if (!strcmp(argv[arg], "/direct")) {
			_d_syscalls_ = TRUE;
		}
		if (!strcmp(argv[arg], "/indirect")) {
			_i_syscalls_ = TRUE;
		}
		if(!strcmp(argv[arg], "/yara")) {
			_yara_ = TRUE;
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

									if (_stack_) {
										thread* stackMonitoringThread = new thread(MonitorThreadCallStack, hThread, threadEntry);
										threads.push_back(stackMonitoringThread);
									}

									if (_stack_spoof_) {
										thread* stackSpoofingMonitoringThread = new thread(GetDetailedStackTraceWithReturnAddresses, targetProcess, hThread);
										threads.push_back(stackSpoofingMonitoringThread);
									}

									if (_backed_) {
										thread* unbackedAddressesMonitoringThread = new thread(MonitorPointersToUnbackedAddresses, hThread, threadEntry);
										threads.push_back(unbackedAddressesMonitoringThread);
									}

								} else {

									active = TRUE;
									cout << "[*] Spawned Thread : " << dec << threadEntry.th32ThreadID << endl;

									if (_stack_) {
										thread* stackMonitoringThread = new thread(MonitorThreadCallStack, hThread, threadEntry);
										threads.push_back(stackMonitoringThread);
									}

									if (_stack_spoof_) {
										thread* stackSpoofingMonitoringThread = new thread(GetDetailedStackTraceWithReturnAddresses, targetProcess, hThread);
										threads.push_back(stackSpoofingMonitoringThread);
									}

									if (_backed_) {
										thread* unbackedAddressesMonitoringThread = new thread(MonitorPointersToUnbackedAddresses, hThread, threadEntry);
										threads.push_back(unbackedAddressesMonitoringThread);
									}
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

void MonitorPointersToUnbackedAddresses(HANDLE hThread, THREADENTRY32 threadEntry32) {
	
	Pe64Utils* modUtils = _pe64Utils;

	SYMBOL_INFO symbolInfo;
	DWORD64 displacement;

	CONTEXT context;
	memset(&context, 0, sizeof(CONTEXT));
	context.ContextFlags = CONTEXT_FULL;

	if (hThread) {
		if (GetThreadContext(hThread, &context)) {

			// Fetching first RIP
			DWORD64 previousRip = context.Rip;

			memset(&symbolInfo, 0, sizeof(SYMBOL_INFO));
			symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
			symbolInfo.MaxNameLen = MAX_SYM_NAME;

			while (_backed_) {

				if (GetThreadContext(hThread, &context)) {

					if (context.Rip != previousRip) {

						if (SymFromAddr(targetProcess, (DWORD_PTR&)context.Rip, &displacement, &symbolInfo)) {
							if (symbolInfo.Name != NULL) {

								std::cout << "\t" << symbolInfo.Name << "+0x" << displacement << std::endl;

							}
						}
						else {
							std::cout << "\tNo symbol found for " << std::hex << (DWORD_PTR)context.Rip << std::endl;
						}

						
						if (!modUtils->isAddressInModulesMemPools(context.Rip)) {

							printBlueAlert("Unbacked return address, analysis...");

							//cout << "\t RIP points to an unbacked address @ " << hex << (DWORD_PTR)context.Rip << endl;

							BYTE paramValue[2048];
							size_t bytesRead;

							if (ReadProcessMemory(targetProcess, (LPVOID)context.Rip, paramValue, sizeof(paramValue), &bytesRead)) {

								//cout << (string)"got that on " << hex << (DWORD_PTR)context.Rip << endl;

								active = FALSE;
								SuspendThread(hThread);
								BOOL problemFound = analyseProcessThreadsStackTrace(targetProcess);
								cout << "\033[0m";
								if (!problemFound) {
									ResumeThread(hThread);
									cout << "\x1B[48;5;22m" << "[OK] No threat detected :)" << "\x1B[0m" << endl;
									active = TRUE;
								}
								else {
									cout << "\033[0m";
									startup();
								}
								cout << "\033[0m";

								if (_debug_) {
									printByteArray(paramValue, bytesRead);
								}
							}
						}

						previousRip = context.Rip;
					}
				}

				_boost_ ? std::this_thread::yield() : Sleep(2);
			}
		}
	}
}


// PID filling
void pidFilling() {
	cout << "\n[*] Choose the PID to monitor : ";
	cin >> targetProcId;
}


void startup() {

	deleteMonitoringWorkerThreads();
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

		/// TODO : Refactor those things in one function !

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

		if (root["DllHookingPatterns"].size() > 0) {
			for (int i = 0; i < root["DllHookingPatterns"].size(); i++) {

				string str_pattern = root["DllHookingPatterns"][i].asString();
				size_t length;

				BYTE* pattern = hexStringToByteArray(str_pattern, length);
				dllPatterns.insert({ pattern , length });

				if (_debug_) {
					cout << "[DEBUG] Loaded Dll Hooking Pattern : \n\t" << endl;
					for (size_t i = 0; i < length; ++i) {
						std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pattern[i]) << " ";
					}
					cout << "\n" << endl;
				}
			}
		}

		if (root["GeneralPatterns"].size() > 0) {
			for (int i = 0; i < root["GeneralPatterns"].size(); i++) {

				string str_pattern = root["GeneralPatterns"][i].asString();
				size_t length;

				BYTE* pattern = hexStringToByteArray(str_pattern, length);
				generalPatterns.insert({ pattern , length });

				if (_debug_) {
					cout << "[DEBUG] Loaded General Pattern : \n\t" << endl;
					for (size_t i = 0; i < length; ++i) {
						std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pattern[i]) << " ";
					}
					cout << "\n" << endl;
				}
			}
		}
	}

	maliciousPatterns.close();

	// Console Control Handling
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);

	// Demanding PID
	pidFilling();

	//cout << " [DEBUG] Working threads table size : " << threads.size() << endl;

	// Opening el famoso Handle on target process identfied by its PID
	targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)targetProcId);
	if (!targetProcess) {
		cout << "[X] Can't find that PID ! Give me a valid one please ! .\n" << endl;
		startup();
	} else {
		cout << "[*] Here we go !\n" << endl;
	}

	if (!SymInitialize(targetProcess, nullptr, TRUE)) {
		std::cerr << "SymInitialize failed. Error code: " << GetLastError() << std::endl;
		exit(-222);
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
	BOOL injected_callbacks_dll = false;

	char* iat_hooking_dll = (char*)"DLLs\\iat.dll";
	char* nt_hooking_dll = (char*)"DLLs\\ntdII.dll";
	char* k32_hooking_dll = (char*)"DLLs\\KerneI32.dll";
	char* callbacks_hooking_dll = (char*)"DLLs\\callbacks.dll";

	DWORD iatDllBufferSize = GetFullPathNameA(iat_hooking_dll, 0, nullptr, nullptr);
	DWORD ntDllBufferSize = GetFullPathNameA(nt_hooking_dll, 0, nullptr, nullptr);
	DWORD k32DllBufferSize = GetFullPathNameA(k32_hooking_dll, 0, nullptr, nullptr);
	DWORD callbacksDllBufferSize = GetFullPathNameA(callbacks_hooking_dll, 0, nullptr, nullptr);

	char* iatDllAbsolutePathBuf = new char[iatDllBufferSize];
	char* ntDllAbsolutePathBuf = new char[ntDllBufferSize];
	char* k32DllAbsolutePathBuf = new char[k32DllBufferSize];
	char* callbacksDllAbsolutePathBuf = new char[callbacksDllBufferSize];

	/// TODO: Print abs paths in verbose

	DWORD absoluteDllPath;

	if (_d_syscalls_) {
	
		absoluteDllPath = GetFullPathNameA(callbacks_hooking_dll, callbacksDllBufferSize, callbacksDllAbsolutePathBuf, nullptr);
		while (!injected_callbacks_dll) {
			if (_v_) {
				cout << "[INFO] Injected callbacks.dll" << endl;
			}
			injected_callbacks_dll = dllLoader.InjectDll(GetProcessId(targetProcess), callbacksDllAbsolutePathBuf, addressOfDll);
		}
	}

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
	
	if (_iat_) {
		modUtils.getFirstModuleIAT();

		cout << "[*] " << modUtils.getIATFunctionsMapping()->size() << " imported functions" << endl;

		functionsNamesImportsMapping = modUtils.getIATFunctionsMapping();
		functionsAddressesOfAddresses = modUtils.getIATFunctionsAddressesMapping();
	}

	ThreadsState.clear();

	modUtils.clearFunctionsNamesMapping();

	/// TODO : Check that they do exist
	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, "ntdll.dll");
	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, "kernel32.dll");
	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, "KERNELBASE.dll");

	// Powershell test
	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, "win32u.dll");
	modUtils.RetrieveExportsForGivenModuleAndFillMap(targetProcess, "user32.dll");


	// Yara
	//YaraUtils yaraUtils(targetProcess); pas ici


	// needs functions mapping to be filled
	if (_nt_ || _k32_ || _iat_ || _d_syscalls_) {

		// Channel 1 : Indirect Syscalls - RSP 

		IpcUtils ipcUtils_ch1(L"\\\\.\\pipe\\beotm_ch1", 
			targetProcess, 
			_v_, 
			dllPatterns, 
			generalPatterns, 
			deleteMonitoringWorkerThreads, 
			startup, 
			_pe64Utils, 
			_yara_
		);

		auto t1 = [&ipcUtils_ch1]() {
			ipcUtils_ch1.initPipeAndWaitForConnection();
			};

		thread* ipc_th1 = new thread(t1);
		threads.push_back(ipc_th1);


		// Channel 2 : Direct Syscalls - RIP

		IpcUtils ipcUtils_ch2(L"\\\\.\\pipe\\beotm_ch2", 
			targetProcess, 
			_v_, 
			dllPatterns, 
			generalPatterns, 
			deleteMonitoringWorkerThreads, 
			startup, 
			_pe64Utils, 
			_yara_
		);

		auto t2 = [&ipcUtils_ch2]() {
			ipcUtils_ch2.initPipeAndWaitForConnection();
			};

		thread* ipc_th2 = new thread(t2);
		threads.push_back(ipc_th2);

		
		// Channel 3 - Hooking - Addrs / Func names / args...
		
		IpcUtils ipcUtils_ch3(L"\\\\.\\pipe\\beotm_ch3", 
			targetProcess, 
			_v_, 
			dllPatterns, 
			generalPatterns, 
			deleteMonitoringWorkerThreads, 
			startup, 
			_pe64Utils,
			_yara_
		);

		auto t3 = [&ipcUtils_ch3]() {
			ipcUtils_ch3.initPipeAndWaitForConnection();
			};

		thread* ipc_th3 = new thread(t3);
		threads.push_back(ipc_th3);

	}

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

	if (_stack_ || _backed_ || _stack_spoof_) {
		
		cout << endl;
		while (true) {
			checkProcThreads(targetProcId);
			Sleep(1500); // Ref : 1500
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
void deleteMonitoringWorkerThreads() {
	if (_debug_) {
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
			cout << "[INFO] " << target << " @ -> " << hex << addr << endl;
		}
		return addr;
	}
	else {
		cerr << target << " not found" << endl;
	}
	return NULL;
}


/*
	///TODO : DOC
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

		//std::mutex m;
		//std::chrono::milliseconds duration(1);

		while (active) {

			if (hThread) {
				if (GetThreadContext(hThread, &context)) {

					if ((previousRip ^ context.Rip) != 0) {

						SYMBOL_INFO symbolInfo;
						DWORD64 displacement;

						memset(&symbolInfo, 0, sizeof(SYMBOL_INFO));
						symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
						symbolInfo.MaxNameLen = MAX_SYM_NAME;

						char* retainedName = NULL;

						BOOL _saved_backed_ = _backed_;

						if (modUtils->isAddressInProcessMemory((LPVOID)(DWORD_PTR)context.Rip)) {
							if (SymFromAddr(targetProcess, (DWORD_PTR&)context.Rip, &displacement, &symbolInfo)) {
								if (symbolInfo.Name != NULL) {
									if (_v_) {
										std::cout << hex << "[" << (DWORD_PTR)context.Rip << "] " << symbolInfo.Name << "+0x" << displacement << std::endl;
									}
									retainedName = symbolInfo.Name;

									if (retainedName != NULL) {
										auto it = stackLevelMonitoredFunctions.find(retainedName);
										if (it != stackLevelMonitoredFunctions.end()) {

											//printf("%s", (char*)symbolInfo.Name);

											std::string msg = (retainedName != NULL) ? std::string(symbolInfo.Name) + " triggered, analysis..." : "No symbol triggered, analysis...";
											printBlueAlert(msg);

											if (_debug_) {
												/// TODO : Les couleurs marchent pas
												cout << "\t\t " << ANSI_COLOR_BG_WHITE << ANSI_COLOR_BLUE << "--------------------------   STACK TRACE    --------------------------\n" << " \t\t\t" << endl;
											}

											active = FALSE;
											//if (!IsThreadSuspended(hThread)){
												SuspendThread(hThread);
											//}
											BOOL problemFound = analyseProcessThreadsStackTrace(targetProcess);
											cout << "\033[0m";
											if (!problemFound) {
												ResumeThread(hThread);
												cout << "\x1B[48;5;22m" << "[OK] No threat detected :)" << "\x1B[0m" << endl;
												active = TRUE;
											}
											else {
												cout << "\033[0m";
												startup();
											}
											cout << "\033[0m";
										}
									}
					
								}
							}
						}
					}

					previousRip = context.Rip;
				
					_boost_ ? std::this_thread::yield() : Sleep(2);


				}
				else {
					cout << "[*] Thread " << threadEntry32.th32ThreadID << " destroyed." << endl;
					ThreadsState.erase((DWORD)threadEntry32.th32ThreadID);
					if (ThreadsState.size() == 0) {
						deleteMonitoringWorkerThreads();
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
					deleteMonitoringWorkerThreads();
					startup();
				}
				//terminate();
				break;
			}
		}

		
		
		} else {
		cout << "[X] Failed to retrieve thread context" << endl;
		deleteMonitoringWorkerThreads();
		startup();
	}
}

std::mutex coutMutex;
DWORD64 GetDetailedStackTraceWithReturnAddresses(HANDLE hProcess, HANDLE hThread) {
	
	DWORD64 returnAddress = NULL;
	CONTEXT context;

	if (hThread != NULL) {

		// init
		if (GetThreadContext(hThread, &context)) {

			DWORD64 previousRsp = context.Rsp;
			DWORD64 previousRbp = context.Rbp;

			while (true) {

					SYMBOL_INFO symbolInfo;
					DWORD64 displacement;

					memset(&symbolInfo, 0, sizeof(SYMBOL_INFO));
					symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
					symbolInfo.MaxNameLen = MAX_SYM_NAME;

					STACKFRAME64 stackFrame64;

					memset(&stackFrame64, 0, sizeof(STACKFRAME64));
					context.ContextFlags = CONTEXT_CONTROL;

					if (GetThreadContext(hThread, &context)) {

						if ((previousRsp != context.Rsp) || (previousRbp != context.Rbp)) {

							stackFrame64.AddrPC.Offset = context.Rip;
							stackFrame64.AddrPC.Mode = AddrModeFlat;
							stackFrame64.AddrFrame.Offset = context.Rbp;
							stackFrame64.AddrFrame.Mode = AddrModeFlat;
							stackFrame64.AddrStack.Offset = context.Rsp;
							stackFrame64.AddrStack.Mode = AddrModeFlat;

							while (StackWalk64(IMAGE_FILE_MACHINE_AMD64,
								hProcess,
								hThread,
								&stackFrame64,
								&context,
								NULL,
								SymFunctionTableAccess64,
								SymGetModuleBase64,
								NULL)) {

								DWORD64 savedRBP;
								if (ReadProcessMemory(hProcess,
									reinterpret_cast<LPCVOID>(stackFrame64.AddrFrame.Offset),
									&savedRBP,
									sizeof(savedRBP),
									NULL)) {

									std::lock_guard<std::mutex> lock(coutMutex);
									std::cout << "Saved RBP: 0x" << std::hex << savedRBP << std::endl;

									DWORD64 returnAddress;
									if (ReadProcessMemory(hProcess,
										reinterpret_cast<LPCVOID>(stackFrame64.AddrFrame.Offset + sizeof(savedRBP)),
										&returnAddress,
										sizeof(returnAddress),
										NULL)) {

										//by SymFromAddr (unsafe function) that was overriding the value of _saved_backed_.
										BOOL _saved_backed_ = _backed_;
										
										if (_pe64Utils->isAddressInProcessMemory((LPVOID)(DWORD_PTR)context.Rip)) {
											if (SymFromAddr(targetProcess, (DWORD_PTR&)returnAddress, &displacement, &symbolInfo)) {
												if (symbolInfo.Name != NULL) {

													//std::lock_guard<std::mutex> lock(coutMutex);
													std::cout << "[ 0x" << std::hex << returnAddress << "] ";
													std::cout << "\t\t\t" << symbolInfo.Name << "+0x" << displacement << std::endl;
												
												}
											}
										}

									}
								}
							}

							cout << "\n\n\n" << endl;

							previousRbp = context.Rbp;
							previousRsp = context.Rsp;
					}
				}

				Sleep(1500);
			}
		}
	}

	return returnAddress;
}


///TODO ------> SymCleanup
/*
	Analyse the call stack of a given process, looking for flagged patterns
	HANDLE hProcess : Target process handle
*/
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
			cout << "[ERROR] INVALID_HANDLE_VALUE returned by CreateToolhelp32Snapshot." << endl;
			exit(-1);
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

								/*
								DWORD64 returnAddress = stackFrame64.AddrReturn.Offset;
								std::cout << "Return Address: 0x" << std::hex << returnAddress << std::endl;
								*/

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
									if (_debug_) {
										cout << "\t\t" << "at " << stackFrame64.AddrPC.Offset << " : " << symbol->Name << endl;
									}

									for (int i = 0; i < 5; i++) {

										BYTE* paramValue = new BYTE[1024];
										size_t bytesRead;

										if (_debug_) {
											cout << "\t\t\t@Param [" << i << "] : " << hex << (DWORD_PTR)stackFrame64.Params[i] << endl;
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

													printRedAlert("Malicious injection detected ! Malicious process killed !");

													//cout << "\x1B[41m" << "[!] Malicious injection detected ! Malicious process killed !\x1B[0m\n" << endl;

													CloseHandle(hProcess);

													for (HANDLE& h : threadsHandles) {
														CloseHandle(h);
													}

													//deleteMonitoringWorkerThreads(); /// ----> Exception lev�e ici ! + probleme bouclage apres detection

													delete[] paramValue;

													deleteMonitoringWorkerThreads();

													return TRUE;

												}
											}
										}

										delete[] paramValue;
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

					printRedAlert("Malicious injection detected ! Malicious process killed !");

					CloseHandle(targetProcess);
					deleteMonitoringWorkerThreads();

					startup();

					/// TODO: verbose ?
					//printByteArray(data, memUtils.getHeapSize(i));
					//printByteArray(pair.first, strlen((const char*)pair.second));

					return TRUE;
				}
			}
			free(data);
		}
		Sleep(2000);
	}
	return FALSE;
}


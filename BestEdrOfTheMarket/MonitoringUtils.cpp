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
#include <amsi.h>

#include "IPCUtils.h"

#include "json/json.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "amsi.lib")

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

//DWORD64 GetDetailedStackTraceWithReturnAddresses(HANDLE, HANDLE);

bool containsSequence(const BYTE*, size_t, const BYTE*, size_t);
//void MonitorPointersToUnbackedAddresses(HANDLE, THREADENTRY32);
bool searchForOccurenceInByteArray(BYTE*, int, BYTE*, int);
//void MonitorThreadCallStack(HANDLE, THREADENTRY32);
DWORD_PTR printFunctionsMappingKeys(const char*);
//BOOL analyseProcessThreadsStackTrace(HANDLE);
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

// Process information block
const char* processPath;

STARTUPINFO startupInfo;
PROCESS_INFORMATION processInfo;



/// <summary>
/// Control Handler for proper deletion of the threads when hitting Ctrl+C/// </summary>
/// <param name="fdwCtrlType">Control type</param>
/// <returns></returns>
BOOL CtrlHandler(DWORD fdwCtrlType) {

	switch (fdwCtrlType) {

	case CTRL_C_EVENT:

		cout << "Terminating..." << endl;
		SymCleanup(targetProcess);
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
BOOL _debug_ = FALSE;
BOOL _boost_ = FALSE;
BOOL _stack_spoof_ = FALSE;
BOOL _d_syscalls_ = FALSE;
BOOL _i_syscalls_ = FALSE;
BOOL _yara_ = FALSE;


BOOL _p_ = FALSE;

int main(int argc, char* argv[]) {

	pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtSuspendProcess");
	pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeProcess");

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
		if (!strcmp(argv[arg], "/debug")) { 
			_debug_ = TRUE;
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

		if(!strcmp(argv[arg], "/p")) {
			
			if(argv[arg+1]) {

				_p_ = TRUE;
				_inherited_p_ = TRUE;
				
				ZeroMemory(&startupInfo, sizeof(startupInfo));
				ZeroMemory(&processInfo, sizeof(processInfo));
				startupInfo.cb = sizeof(startupInfo);
				startupInfo.dwFlags = STARTF_USESHOWWINDOW;
				startupInfo.wShowWindow = SW_SHOW;

				std::cout << "[*] Spawning " << (char*)argv[arg + 1] << " ..." << std::endl;

				LPWSTR converted = ConvertCharToLPWSTR(argv[arg + 1]);

				if (!CreateProcess(
					NULL,                     
					converted,
					NULL,                      
					NULL,                      
					FALSE,                     
				    CREATE_NEW_CONSOLE,
					NULL,                      
					NULL,                      
					&startupInfo,              
					&processInfo               
				)) {
					std::cerr << "[X] Failed to spawn process. Error code: " << GetLastError() << std::endl;
					
					printLastError();
					
					//_p_ = FALSE;
					startup(); // Si ça casse ça vient de là
					exit(-1);
				}

				arg += 1;
				
				Sleep(100);

				targetProcId = processInfo.dwProcessId;
			}
		}

	}

	startup();

	return 0;
}


// PID filling
void pidFilling() {
	cout << "\n[*] Choose the PID to monitor : ";
	cin >> targetProcId;
}

/*
	Startup function, called at the beginning of the program. It fills the maps with the content of the JSON files and initializes the monitoring threads.
*/

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
	if (!_p_) {
		pidFilling();
	}

	// Opening el famoso Handle on target process identfied by its PID
	targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)targetProcId);
	Sleep(5);
	pfnNtSuspendProcess(targetProcess);

	if (!targetProcess) {
		cout << "[X] Can't find that PID ! Give me a valid one please ! .\n" << endl;
		startup();
	}
	else {
		cout << "[*] Here we go !\n" << endl;
	}

	//cout << " [DEBUG] Working threads table size : " << threads.size() << endl;

	if (!SymInitialize(targetProcess, nullptr, TRUE)) {
		std::cerr << "SymInitialize failed. Error code: " << GetLastError() << std::endl;
		exit(-222);
	}

	Pe64Utils modUtils(targetProcess);
	_pe64Utils = &modUtils;
	modUtils.enumerateProcessModulesAndTheirPools();
	modUtils.enumerateMemoryRegionsOfProcess();

	DllLoader dllLoader(targetProcess);

	LPVOID addressOfDll;
	
	BOOL injected_iat_dll = false;
	BOOL injected_nt_dll = false;
	BOOL injected_k32_dll = false;
	BOOL injected_callbacks_dll = false;
	BOOL injected_magic_bp_dll = false;

	char* iat_hooking_dll = (char*)"DLLs\\iat.dll";
	char* nt_hooking_dll = (char*)"DLLs\\ntdII.dll";
	char* k32_hooking_dll = (char*)"DLLs\\KerneI32.dll";
	char* callbacks_hooking_dll = (char*)"DLLs\\callbacks.dll";
	char* magicbp_dll = (char*)"DLLs\\magicbp.dll";

	DWORD iatDllBufferSize = GetFullPathNameA(iat_hooking_dll, 0, nullptr, nullptr);
	DWORD ntDllBufferSize = GetFullPathNameA(nt_hooking_dll, 0, nullptr, nullptr);
	DWORD k32DllBufferSize = GetFullPathNameA(k32_hooking_dll, 0, nullptr, nullptr);
	DWORD callbacksDllBufferSize = GetFullPathNameA(callbacks_hooking_dll, 0, nullptr, nullptr);
	DWORD magicbpDllBufferSize = GetFullPathNameA(magicbp_dll, 0, nullptr, nullptr);

	char* iatDllAbsolutePathBuf = new char[iatDllBufferSize];
	char* ntDllAbsolutePathBuf = new char[ntDllBufferSize];
	char* k32DllAbsolutePathBuf = new char[k32DllBufferSize];
	char* callbacksDllAbsolutePathBuf = new char[callbacksDllBufferSize];
	char* magicbpDllAbsolutePathBuf = new char[magicbpDllBufferSize];

	/// TODO: Print abs paths in verbose

	DWORD absoluteDllPath;

	if (_d_syscalls_ || _stack_) {
	
		absoluteDllPath = GetFullPathNameA(callbacks_hooking_dll, callbacksDllBufferSize, callbacksDllAbsolutePathBuf, nullptr);
		while (!injected_callbacks_dll) {
			if (_v_) {
				cout << "[INFO] Injected callbacks.dll" << endl;
			}
			injected_callbacks_dll = dllLoader.InjectDll(GetProcessId(targetProcess), callbacksDllAbsolutePathBuf, addressOfDll);
		}
	}

	if (_i_syscalls_) {
		absoluteDllPath = GetFullPathNameA(magicbp_dll, magicbpDllBufferSize, magicbpDllAbsolutePathBuf, nullptr);
		while (!injected_magic_bp_dll) {
			if (_v_) {
				cout << "[INFO] Injected magicbp.dll" << endl;
			}
			injected_magic_bp_dll = dllLoader.InjectDll(GetProcessId(targetProcess), magicbpDllAbsolutePathBuf, addressOfDll);
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
		Sleep(500); // avoid conflicts
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
	
	if (_iat_) {
		modUtils.getFirstModuleIAT();

		cout << "[*] " << modUtils.getIATFunctionsMapping()->size() << " imported functions" << endl;

		//functionsNamesImportsMapping = modUtils.getIATFunctionsMapping();
		//functionsAddressesOfAddresses = modUtils.getIATFunctionsAddressesMapping();
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


	HeapUtils heapUtils(targetProcess);

	// Heap Monitoring 
	/*if (_heap_) {
		thread* heapMonThread = new thread(monitorHeapForProc, heapUtils);
		threads.push_back(heapMonThread);
	}*/

	// needs functions mapping to be filled
	if (_nt_ || _k32_ || _iat_ || _stack_ || _d_syscalls_ || _i_syscalls_) {

		// Channel 1 : Indirect Syscalls - RSP 

		IpcUtils ipcUtils_ch1(L"\\\\.\\pipe\\beotm_ch1", 
			targetProcess, 
			_v_, 
			dllPatterns, 
			generalPatterns,
			deleteMonitoringWorkerThreads, 
			startup,
			_pe64Utils,
			heapUtils,
			_heap_,
			_yara_,
			_stack_,
			_d_syscalls_
		);

		ipcUtils_ch1.setPatterns(
			dllPatterns,
			generalPatterns,
			&stackPatterns,
			&heapPatterns
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
			heapUtils,
			_heap_,
			_yara_,
			_stack_,
			_d_syscalls_
		);

		ipcUtils_ch2.setPatterns(
			dllPatterns,
			generalPatterns,
			&stackPatterns,
			&heapPatterns
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
			heapUtils,
			_heap_,
			_yara_,
			_stack_,
			_d_syscalls_
		);

		ipcUtils_ch3.setPatterns(
			dllPatterns,
			generalPatterns,
			&stackPatterns,
			&heapPatterns
		);

		auto t3 = [&ipcUtils_ch3]() {
			ipcUtils_ch3.initPipeAndWaitForConnection();
			};

		thread* ipc_th3 = new thread(t3);
		threads.push_back(ipc_th3);

	}

	functionsNamesMapping = modUtils.getFunctionsNamesMapping();

	if (_ssn_) {
		
		for (int i = 0; i < routinesToCrush.size(); i++) {
			doingSomethingWithTheSyscall(targetProcess, (DWORD_PTR)modUtils.getFunctionsNamesMapping()->at(
				routinesToCrush.at(i)
			));
		}

	}

	pfnNtResumeProcess(targetProcess);

	while (true) {
		Sleep(INFINITE);
	}

}

/*
Function for proper deletion of monitoring threads, invoked when hitting Ctrl+C / when the process is terminated 
*/
void deleteMonitoringWorkerThreads() {

	if(targetProcess != NULL) {
		SymCleanup(targetProcess);
	}

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

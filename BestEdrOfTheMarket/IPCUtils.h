#pragma once

/// TODO : 00007FF83EE4ACF4

#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <iostream>
#include <vector>
#include <json/json.h> 
#include <string>
#include <yara.h>
#include <filesystem>

#include "ErrorsReportingUtils.h"
#include "ColorsUtils.h"
#include "BytesSequencesUtils.h"
#include "ReportingUtils.h"
#include "PatchingUtils.h"
#include "AmsiUtils.h"

#pragma comment(lib, "amsi.lib")

namespace fs = std::filesystem;

#define PIPE_BUFFER_SIZE 512

typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG(NTAPI* NtResumeProcess)(HANDLE ProcessHandle);

NtSuspendProcess pfnNtSuspendProcess;
NtResumeProcess pfnNtResumeProcess;

typedef void (*DeleteMonitoringWorkerThreads)();
typedef void (*Startup)();

HANDLE tProcess_global;
DeleteMonitoringWorkerThreads dmwt_global;
Startup startup_global;

BOOL _stack_val_global_ = FALSE;
BOOL _yara_enabled_global_ = FALSE;

HRESULT hr;
HAMSICONTEXT amsiContext = NULL;

PVOID AmsiScanOpenSessionPtr = NULL;
PVOID AmsiScanBufferPtr = NULL;
PVOID EtwEventWritePtr = NULL;
PVOID NtTraceEventsPtr = NULL;

BOOL _inherited_p_ = FALSE;

std::string currentDefensiveMethdod = "";

int numberOfUnbackedFunctionAddresses = 0;

int callback_function(
	YR_SCAN_CONTEXT* context,
	int message,
	void* message_data,
	void* user_data) {

	if (message == CALLBACK_MSG_RULE_MATCHING) {

		printRedAlert("Malicious process detected ! Killing it .... ");
		TerminateProcess(tProcess_global, -1);

		YR_RULE* rule = (YR_RULE*)message_data;

		std::string jsonReport = yaraRulesReportingJson(
			GetProcessId(tProcess_global),
			GetProcessPathByPID(GetProcessId(tProcess_global), tProcess_global),
			std::string("Defensive technique revealed a YARA pattern matching."),
			std::string(context->rules->rules_table->identifier),
			std::string(context->rules->rules_table->metas->string)
		);

		std::cout << jsonReport << std::endl;

		printAsciiDump(
			(BYTE*)context->rules->rules_table->strings[0].string, 
			context->rules->rules_table->strings[0].length
		);

		MessageBoxA(NULL, (LPCSTR)"Malicious process detected ! (Yara)", "Best Edr Of The Market", MB_ICONEXCLAMATION);

		printRedAlert("Malicious process terminated !");
		
		
		if (!_inherited_p_) {
			dmwt_global();
			startup_global();
		} else {
			exit(0);
		}

		return CALLBACK_EVENT;
	}

	return CALLBACK_CONTINUE;
}

YR_COMPILER* compiler;
YR_SCANNER* scanner = nullptr;
FILE* file;
YR_RULES* rules;

int result;

// Temporary 
int initYaraUtils() {

	yr_initialize();
	yr_compiler_create(&compiler);

	/// TODO : retrieve all the files that ends with .yara

	std::string path = ".\\YARA\\";
	std::cout << "\n" << std::endl;
	for (const auto& entry : fs::directory_iterator(path)) {

		if (entry.path().extension() == ".yara" || entry.path().extension() == ".yar") {

			const char* rule_file_path = entry.path().string().c_str(); 

			//std::cout << "[YARA] Added rule file : " << rule_file_path << "\n";

			FILE* file;
			fopen_s(&file, rule_file_path, "r");

			result = yr_compiler_add_file(compiler, file, NULL, rule_file_path);

			if (result != 0) {
				std::cerr << "Error compiling YARA rule file" << std::endl;
				yr_compiler_destroy(compiler);
				yr_finalize();
				return 1;

				fclose(file);
			}
		}
	}
		


	result = yr_compiler_get_rules(compiler, &rules);
	
	if (result != 0) {
		std::cerr << "Error retrieving compiled rules" << std::endl;
		yr_compiler_destroy(compiler);
		yr_finalize();
		return 1;
	}

	int scan_res = yr_scanner_create(rules, &scanner);

	yr_scanner_set_callback(scanner, (YR_CALLBACK_FUNC)callback_function, NULL);

	if (scan_res != 0 || scanner == nullptr) {
		std::cerr << "Error while creating a scanner" << std::endl;
	}

	return 0;
}

class IpcUtils {

private: 

	//static std::vector<HANDLE> pipes;

	HANDLE hPipe;
	HANDLE targetProcess;
	BYTE buffer[1024];
	DWORD bytesRead;
	LPCWSTR pipeName;
	BOOL _v_;

	// Legacy patterns
	std::unordered_map<BYTE*, SIZE_T>& dllPatterns;
	std::unordered_map<BYTE*, SIZE_T>& generalPatterns;
	std::unordered_map<int, BYTE*>* stackPatterns;
	std::unordered_map<BYTE*, SIZE_T>* heapPatterns;

	DeleteMonitoringWorkerThreads deleteMonitoringFunc;
	Startup startupFunc;

	Pe64Utils *pe64Utils;
	HeapUtils heapUtils;
	std::unordered_map<std::string, DWORD_PTR>* functionsNamesMapping; // useless ?

	SYMBOL_INFO symbolInfo;
	DWORD64 displacement = 0;

	std::vector<HANDLE>* hThreads;

	// Legacy params
	BOOL heapEnabled;
	BOOL yaraEnabled;
	BOOL stackEnabled ;
	BOOL directSyscallEnabled;



	PatchingMitigationUtils patchUtils;

public:

	void setPatterns(
		std::unordered_map<BYTE*, SIZE_T>& dll_p,
		std::unordered_map<BYTE*, SIZE_T>& general_p,
		std::unordered_map<int, BYTE*> *stack_p,
		std::unordered_map<BYTE*, SIZE_T>* heapPatterns
	) {
		this->dllPatterns = dll_p;
		this->generalPatterns = general_p;
		this->stackPatterns = stack_p;
		this->heapPatterns = heapPatterns;
	}

	IpcUtils(LPCWSTR pipeName,
		HANDLE& tProcess,
		BOOL& verbose,
		std::unordered_map<BYTE*, SIZE_T>& dllPatterns,
		std::unordered_map<BYTE*, SIZE_T>& generalPatterns,
		DeleteMonitoringWorkerThreads f1,
		Startup f2,
		Pe64Utils* pe64utils,
		HeapUtils& heapUtils,
		BOOL& heap,
		BOOL& yara,
		BOOL& stack,
		BOOL& dsyscalls
	) :
		pipeName(pipeName),
		targetProcess(tProcess),
		_v_(verbose),
		dllPatterns(dllPatterns),
		generalPatterns(generalPatterns),
		deleteMonitoringFunc(f1),
		startupFunc(f2),
		pe64Utils(pe64utils),
		heapUtils(heapUtils),
		heapEnabled(heap),
		yaraEnabled(yara),
		stackEnabled(stack),
		directSyscallEnabled(dsyscalls),
		patchUtils(tProcess) {

		pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtSuspendProcess");
		pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeProcess");


		if (pe64Utils->isModulePresent("C:\\Windows\\SYSTEM32\\amsi.dll")) {
			AmsiScanBufferPtr = GetProcAddress(GetModuleHandleA("amsi.dll"), "AmsiScanBuffer");
			AmsiScanOpenSessionPtr = GetProcAddress(GetModuleHandleA("amsi.dll"), "AmsiScanOpenSession");
		}

		EtwEventWritePtr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
		NtTraceEventsPtr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTraceEvent");

		initYaraUtils();
		functionsNamesMapping = pe64Utils->getFunctionsNamesMapping();
		hThreads = pe64Utils->getThreads();

		// globals for yara
		tProcess_global = tProcess;
		dmwt_global = f1;
		startup_global = f2;

		_stack_val_global_ = stack;
		_yara_enabled_global_ = yara;

	}

	~IpcUtils() {
		/*yaraUtils->destroyCompilerAndFinalize();
		delete yaraUtils;*/
	}


	void amsitest(PVOID buffer, ULONG length) {
		HAMSICONTEXT amsiContext;
		HRESULT hr = AmsiInitialize(L"MyApp", &amsiContext);
		if (FAILED(hr)) {
			std::cerr << "Failed to initialize AMSI\n";
			return;
		}

		HAMSISESSION session;
		hr = AmsiOpenSession(amsiContext, &session);
		if (FAILED(hr)) {
			std::cerr << "Failed to open AMSI session\n";
			AmsiUninitialize(amsiContext);
			return;
		}

		AMSI_RESULT result;
		hr = AmsiScanBuffer(amsiContext, buffer, length, L"MyContent", session, &result);
		if (SUCCEEDED(hr)) {
			if (result == AMSI_RESULT_DETECTED) {
				std::cout << "Malicious content detected!\n";
			}
			else {
				std::cout << "No malicious content detected.\n";
			}
		}
		else {
			std::cerr << "Failed to scan buffer\n";
		}

		AmsiCloseSession(amsiContext, session);
		AmsiUninitialize(amsiContext);
	}

	void alertAndKillThatProcess(HANDLE hProc) {

		TerminateProcess(hProc, -1);
		CloseHandle(hProc);
		CloseHandle(hPipe);

		HWND hWndParent = NULL;

		int msgbox = MessageBoxA(NULL, "Malicious process detected (DLL) !", "Best Edr Of The Market", MB_ICONEXCLAMATION);
		if (msgbox == IDOK) {
			SetForegroundWindow(hWndParent);
		}

		printRedAlert("Malicious process was terminated !");
	}


	HANDLE initPipeAndWaitForConnection() {

		memset(&symbolInfo, 0, sizeof(SYMBOL_INFO));
		symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
		symbolInfo.MaxNameLen = MAX_SYM_NAME;

		HANDLE hPipe;
		char buffer[256];
		DWORD bytesRead;

		while (true) {

			hPipe = CreateNamedPipe(
				pipeName,
				PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
				PIPE_UNLIMITED_INSTANCES,
				PIPE_BUFFER_SIZE,
				PIPE_BUFFER_SIZE,
				0,
				NULL
			);

			//pipes.push_back(hPipe);

			if (hPipe == INVALID_HANDLE_VALUE || hPipe == NULL) {
				std::cerr << "Error when initializing BEOTM pipe." << std::endl;
				printLastError();
				exit(-25);
			}

			if (ConnectNamedPipe(hPipe, nullptr)) {
				if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, nullptr)) {

					std::string jsonString((char*)(buffer), bytesRead);

					Json::Value root;
					Json::CharReaderBuilder reader;
					std::istringstream jsonStream(jsonString);

					if (Json::parseFromStream(reader, jsonStream, &root, nullptr)) {

						if (_v_) { // [JSON] ?
							std::cout << "\n" << root.toStyledString() << std::endl;
						}
						
						if (root.isMember("RSP")) {

							//pfnNtSuspendProcess(targetProcess);

							std::string rspPointer = root["RSP"].asString();

							DWORD_PTR targetAddress = std::stoull(rspPointer, nullptr, 16);

							if (!pe64Utils->isAddressInModulesMemPools(targetAddress)) {

								std::cout << "\n";
								std::string alertText = "Indirect Syscall Detected !";
								printRedAlert(alertText);

								std::string report = directSyscallReportingJson(
									GetProcessId(targetProcess),
									std::string(GetProcessPathByPID((DWORD)GetProcessId(targetProcess), targetProcess)),
									std::string("Indirect Syscalls detection through stack pointers health Check."),
									rspPointer
								);

								std::cout << "\n" << report << "\n" << std::endl;

								alertAndKillThatProcess(targetProcess);
								deleteMonitoringFunc();
								startupFunc();
							}

							//pfnNtResumeProcess(targetProcess);

						}

						if (root.isMember("RIP")
							&& root["RIP"].asString() != "00007FFA71EEC5F4"
							&& root["RIP"].asString() != "00007FFA71EEACF4"
							&& root["RIP"].asString() != "00007FF83EE4ACF4"
							&& root["RIP"].asString() != "00007FF83EE4C5F4"
							&& root["RIP"].asString() != "00007FF83EE4A034") {

							pfnNtSuspendProcess(targetProcess);

							std::string ripPointer = root["RIP"].asString();

							stackEnabled = _stack_val_global_;

							if (stackEnabled) {
								analyzeCompleteProcessThreadsStackTrace(targetProcess);
							}

							DWORD_PTR targetAddress = std::stoull(ripPointer, nullptr, 16);

							SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
							SymInitialize(targetProcess, NULL, TRUE);

							if (directSyscallEnabled) {

								
								if (!SymFromAddr(targetProcess, (DWORD_PTR&)targetAddress, &displacement, &symbolInfo)) {
									
									std::cout << "\n";
									std::string alertText = "Direct Syscall stub at " + ripPointer;
									printRedAlert(alertText);

									std::string report = directSyscallReportingJson(
										GetProcessId(targetProcess),
										std::string(GetProcessPathByPID((DWORD)GetProcessId(targetProcess), targetProcess)),
										std::string("Direct Syscall detection through callbacks interceptions."),
										ripPointer
									);

									std::cout << "\n" << report << "\n" << std::endl;

									alertAndKillThatProcess(targetProcess);
									deleteMonitoringFunc();
									startupFunc();
								
								} else {
					
									pfnNtSuspendProcess(targetProcess);

									if (_v_) { std::cout << "\t -> " << symbolInfo.Name << std::endl; }
									
									pfnNtResumeProcess(targetProcess);

								}

							}

							pfnNtResumeProcess(targetProcess);

						}

						// inactive for now

						if (root.isMember("Thread")) {

							std::cout << "Thread Created" << std::endl;
						}

						int patchResultAmsiOpenSession;
						int patchResultAmsiScanBuffer;
						int NtTraceEventPatchResult;
						int EtwEventWritePatchResult;

						if (root.isMember("Function")) {

							pfnNtSuspendProcess(targetProcess);

							pe64Utils->enumerateMemoryRegionsOfProcess();

							if (!root.isMember("Hexdump")) {

								PVOID AmsiOpenSessionAddr = GetProcAddress(LoadLibraryA("amsi"), "AmsiOpenSession");
								PVOID AmsiScanBufferAddr = GetProcAddress(LoadLibraryA("amsi"), "AmsiScanBuffer");

								if (pe64Utils->isModulePresent("C:\\Windows\\SYSTEM32\\amsi.dll")) {

									patchResultAmsiOpenSession = patchUtils.checkAmsiOpenSession(AmsiOpenSessionAddr);
									patchResultAmsiScanBuffer = patchUtils.checkAmsiScanBuffer(AmsiScanBufferAddr);

									if (patchResultAmsiOpenSession == 0 || patchResultAmsiScanBuffer == 0) {

										printRedAlert("Malicious process detected ! (AMSI Patch). Killing it...");
										MessageBoxA(NULL, (LPCSTR)"Malicious process detected ! (AMSI Patching)", "Best Edr Of The Market", MB_ICONEXCLAMATION);

										TerminateProcess(targetProcess, -1);
										deleteMonitoringFunc();
										startupFunc();

									}
								}

								/*NtTraceEventPatchResult = patchUtils.checkNtTraceEvents(GetProcAddress(LoadLibraryA("ntdll"), "NtTraceEvent"));

								EtwEventWritePatchResult = patchUtils.checkEtwEventWrite(GetProcAddress(LoadLibraryA("ntdll"), "EtwEventWrite"));
								*/

								if (NtTraceEventPatchResult == 0 || EtwEventWritePatchResult == 0) {
									printRedAlert("Malicious process detected ! (ETW Patch). Killing it...");
									MessageBoxA(NULL, (LPCSTR)"Malicious process detected ! (ETW Patching)", "Best Edr Of The Market", MB_ICONEXCLAMATION);

									TerminateProcess(targetProcess, -1);
									deleteMonitoringFunc();
									startupFunc();
								}

								// Patching mitigation
								if (pe64Utils->isModulePresent("C:\\Windows\\SYSTEM32\\amsi.dll")) {
									patchUtils.checkAmsiOpenSession(AmsiScanOpenSessionPtr);
								}

								if (heapEnabled) {

									heapUtils.retrieveHeapRegions(_v_);

									for (int i = 0; i < heapUtils.getHeapCount(); i++) {
										BYTE* data = heapUtils.getHeapRegionContent(i);
										
										if (yaraEnabled) {
											yr_scanner_scan_mem(scanner, (BYTE*)data, heapUtils.getHeapRegionSize(i));
										}
										
										for (const auto& pair : *heapPatterns) {
												if (containsSequence(data, heapUtils.getHeapRegionSize(i), pair.first, pair.second)) {
													printRedAlert("Malicious process detected !!! (Heap). Killing it...");
													std::string report = heapReportingJson(
														GetProcessId(targetProcess),
														std::string(GetProcessPathByPID((DWORD)GetProcessId(targetProcess), targetProcess)),
														std::string("Heap Regions Analysis"),
														(DWORD_PTR)heapUtils.getHeapAddress(i),
														std::string(bytesToHexString(pair.first, pair.second))
													);

													
													std::cout << report << std::endl;
													
													
													MessageBoxA(NULL, (LPCSTR)"Malicious process detected ! (Heap)", "Best Edr Of The Market", MB_ICONEXCLAMATION);

													TerminateProcess(targetProcess, -1);
													deleteMonitoringFunc();
													startupFunc();
											}
											
										}
									}

								}

								std::string routineName = root["Function"].asString();

								printBlueAlert("Intercepted " + routineName);

								if (root.isMember("Size")) {
									std::string size = root["Size"].asString();

								}

								LPCVOID addrPointer;
								BYTE* addr;
								std::string concernedAddress;

								if (root.isMember("RawData")) {

									concernedAddress = root["RawData"].asCString();

									size_t capturedDataSize = (size_t)strlen(root["RawData"].asCString());

									if (capturedDataSize > 0) {
										addr = hexStringToBytes(concernedAddress, capturedDataSize);
										memccpy(&addrPointer, addr, 8, 8);
										//BYTE rAddr[8] = { addr[7], addr[6], addr[5], addr[4], addr[3], addr[2], addr[1], addr[0] };
									}
								}

								if (root.isMember("StringData")) {

									concernedAddress = root["StringData"].asCString();

									size_t capturedDataSize = (size_t)strlen(root["StringData"].asCString());

									if (capturedDataSize > 0) {
										addrPointer = hexStringToLPCVOID(root["StringData"].asCString());
									}
								}

								BYTE dump[1024];
								size_t dumpBytesRead;

								if (ReadProcessMemory(targetProcess, (LPCVOID)addrPointer, dump, sizeof(dump), &dumpBytesRead)) {

									//std::cout << "je analize" << std::endl;

									if (yaraEnabled) {

										//amsitest((LPVOID)dump, dumpBytesRead);

										if (yr_scanner_scan_mem(scanner, dump, dumpBytesRead)) {
											alertAndKillThatProcess(targetProcess);
											deleteMonitoringFunc();
											startupFunc();
										
										}
									}

									for (const auto& pair : dllPatterns) {
										if (containsSequence(dump, dumpBytesRead, pair.first, pair.second)) {

											alertAndKillThatProcess(targetProcess);

											std::string report = dllHookingReportingJson(
												GetProcessId(targetProcess),
												std::string(GetProcessPathByPID((DWORD)GetProcessId(targetProcess), targetProcess)),
												std::string("Hooked ") + std::string(routineName),
												(std::string)"0x" + concernedAddress,
												(std::string)bytesToHexString(pair.first, pair.second),
												"DLL Patterns",
												(std::string)bytesToHexString(dump, dumpBytesRead)
											);

											std::cout << "\n" << report << "\n" << std::endl;

											deleteMonitoringFunc();
											startupFunc();
										}
									}

									for (const auto& pair : generalPatterns) {
										if (containsSequence(dump, dumpBytesRead, pair.first, pair.second)) {
											alertAndKillThatProcess(targetProcess);

											std::string report = dllHookingReportingJson(
												GetProcessId(targetProcess),
												std::string(GetProcessPathByPID((DWORD)GetProcessId(targetProcess), targetProcess)),
												std::string("DLL Hooking on ") + std::string(routineName),
												(std::string)"0x" + concernedAddress,
												(std::string)bytesToHexString(pair.first, pair.second),
												"General Patterns",
												(std::string)bytesToHexString(dump, dumpBytesRead)
											);

											std::cout << "\n" << report << "\n" << std::endl;

											deleteMonitoringFunc();
											startupFunc();
										}
									}
								}

							} else {
								
								// Inactive for now

								const char* receivedBuffer = root["Hexdump"].asCString();

								size_t bytesBufferSize;
								BYTE* bytesBuffer = convertHexToBytes(receivedBuffer, bytesBufferSize);
								yr_scanner_scan_mem(scanner, bytesBuffer, bytesBufferSize);
							}

							pfnNtResumeProcess(targetProcess);

						}
					}
				}
			}
		}

		return hPipe;
	}
	
	void terminatePipeConnection() {
		if (!DisconnectNamedPipe(hPipe)) {
			std::cerr << "Error when disconnecting from BEOTM pipe." << std::endl;
			CloseHandle(hPipe);
			exit(-28);
		}
	}


	BOOL analyzeCompleteProcessThreadsStackTrace(HANDLE hProcess) {

		std::vector<HANDLE> threadsHandles;

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
				std::cout << "[ERROR] INVALID_HANDLE_VALUE returned by CreateToolhelp32Snapshot." << std::endl;
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

								CHAR* lastResolvedSymbol = NULL;
								int set = 0;

								int i = 0;

								if (_v_) {
									std::cout << "\n\n[*] Captured Stack Frame : " << std::endl;
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

					
									i += 1;

									DWORD64 returnAddress = stackFrame64.AddrReturn.Offset;
									//std::cout << (int)i << " - Return Address: 0x" << std::hex << returnAddress << std::endl;

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

									yaraEnabled = _yara_enabled_global_;


									IMAGEHLP_SYMBOL64* symbol = (IMAGEHLP_SYMBOL64*)malloc(sizeof(IMAGEHLP_SYMBOL64) + 1024);
									symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
									symbol->MaxNameLength = 1024;


									if (SymFromAddr(targetProcess, (DWORD_PTR&)stackFrame64.AddrPC.Offset, &displacement, &symbolInfo)) {
										if (symbolInfo.Name != NULL) {
											 
										yaraEnabled = _yara_enabled_global_;

											if (_v_) { 
												std::cout << "\t\t " << stackFrame64.AddrPC.Offset << " -> " << symbolInfo.Name << std::endl;
											}

											for (int i = 0; i < 5; i++) {

												BYTE* paramValue = new BYTE[1024];
												size_t bytesRead;

												if (ReadProcessMemory(hProcess, (LPCVOID)stackFrame64.Params[i], paramValue, 1024, &bytesRead)) {
																										
													if (yaraEnabled) {
														yr_scanner_scan_mem(scanner, paramValue, bytesRead);
													}

													for (const auto& pair : *stackPatterns) {

														int id = pair.first;
														BYTE* pattern = pair.second;
														size_t patternSize = strlen(reinterpret_cast<const char*>(pattern));
	
														if (containsSequence(paramValue, bytesRead, pair.second, patternSize)) {
																
															printRedAlert("Malicious Process Detected ! (Stacked Functions Arguments Analysis). Killing it...");
															std::string symbolName;
															if (symbolInfo.Name != NULL) {
																symbolName = symbolInfo.Name;
															}
															else {
																symbolName = "Unknown Symbol";
															}

															std::string report = stackFrameReportingJson(
																GetProcessId(hProcess),
																std::string(GetProcessPathByPID(GetProcessId(hProcess), hProcess)),
																std::string("Stacked Functions Arguments Analysis (Normal patterns)"),
																std::string(symbolName),
																(DWORD_PTR)stackFrame64.AddrPC.Offset,
																(std::string)bytesToHexString(pattern, patternSize),
																(std::string)bytesToHexString(paramValue, bytesRead)	
															);

															MessageBoxA(NULL, (LPCSTR)"Malicious process detected ! (Stack)", "Best Edr Of The Market", MB_ICONEXCLAMATION);

															std::cout << report << std::endl;

															TerminateProcess(hProcess, -1);
															//alertAndKillThatProcess(hProcess);
															deleteMonitoringFunc();
															startupFunc();
														}
													}
													
												}
											}
										}
									}
									else {

										if (_v_) {
											std::cout << "\t\t " << std::hex << (DWORD_PTR)stackFrame64.AddrPC.Offset << std::endl;
										}

										if(pe64Utils->isAddressInModulesMemPools(stackFrame64.AddrPC.Offset)) {
										
											printGreenAlert("Non resolved address in modules memory pools.");
										
										} else {
											
											printOrangeAlert("Code injection may be occuring !");
											
											if (yaraEnabled) {
												printOrangeAlert("Scanning the memory region for patterns...");
												
												int indexOfMemoryRegionOfOfsset = pe64Utils->indexOfMemoryRegion((LPVOID)stackFrame64.AddrPC.Offset);

												if(pe64Utils->memoryRegionsContainsIndex(indexOfMemoryRegionOfOfsset)) {

													int sizeOfRegion = pe64Utils->getSizeOfMemoryRegionByItsIndex(indexOfMemoryRegionOfOfsset);

													if (sizeOfRegion > 0) {
	
														BYTE* content = new BYTE[sizeOfRegion];
														size_t bytesRead;
														if (ReadProcessMemory(
															hProcess,
															(LPCVOID)pe64Utils->getStartOfMemoryRegion(indexOfMemoryRegionOfOfsset),
															content,
															sizeOfRegion,
															&bytesRead
														)) {

															// analyze content
															yr_scanner_scan_mem(scanner,
																content,
																pe64Utils->getSizeOfMemoryRegionByItsIndex(indexOfMemoryRegionOfOfsset)
															);
														}

														delete[] content;

														yaraEnabled = _yara_enabled_global_;
													}


												} else {
													std::cout << "Memory region does not contain index" << std::endl;
												}
											}
										}
									}
								}
							}
						}
					}
				} while (Thread32Next(snapshot, &threadEntry));

				for (HANDLE& h : threadsHandles) {
					CloseHandle(h);
				}

				return FALSE;

			}

		}
	}




};







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

#include "ErrorsReportingUtils.h"
#include "ColorsUtils.h"
#include "BytesSequencesUtils.h"
#include "ReportingUtils.h"

#define PIPE_BUFFER_SIZE 512

typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG(NTAPI* NtResumeProcess)(HANDLE ProcessHandle);

typedef void (*DeleteMonitoringWorkerThreads)();
typedef void (*Startup)();

HANDLE tProcess_global;
DeleteMonitoringWorkerThreads dmwt_global;
Startup startup_global;

BOOL _stack_val_global_ = FALSE;
BOOL _yara_enabled_global_ = FALSE;

int callback_function(
	YR_SCAN_CONTEXT* context,
	int message,
	void* message_data,
	void* user_data) {

	if (message == CALLBACK_MSG_RULE_MATCHING) {
		
		printRedAlert("Malicious process detected ! Killing it .... ");

		YR_RULE* rule = (YR_RULE*)message_data;

		std::string jsonReport = yaraRulesReportingJson(
			GetProcessId(tProcess_global),
			GetProcessPathByPID(GetProcessId(tProcess_global), tProcess_global),
			std::string("Yara rule matching detected."),
			std::string(context->rules->rules_table->identifier),
			std::string(context->rules->rules_table->metas->string)
		);

		std::cout << jsonReport << std::endl;

		printAsciiDump(
			(BYTE*)context->rules->rules_table->strings[0].string, 
			context->rules->rules_table->strings[0].length
		);

		TerminateProcess(tProcess_global, -1);

		MessageBoxA(NULL, (LPCSTR)"Malicious process detected ! (Yara)", "Best Edr Of The Market", MB_ICONEXCLAMATION);

		printRedAlert("Malicious process terminated !");

		dmwt_global();
		startup_global();

		return CALLBACK_ERROR;
	}

	return CALLBACK_CONTINUE;
}

YR_COMPILER* compiler;
YR_SCANNER* scanner = nullptr;
FILE* file;
YR_RULES* rules;

// Temporary 
int initYaraUtils() {

	yr_initialize();
	yr_compiler_create(&compiler);

	/// TODO : retrieve all the files that ends with .yara
	const char* rule_file_path = "MsfvenomWho.yara";

	fopen_s(&file, rule_file_path, "r");

	int result = yr_compiler_add_file(compiler, file, NULL, rule_file_path);
	if (result != 0) {
		std::cerr << "Error compiling YARA rule file" << std::endl;
		yr_compiler_destroy(compiler);
		yr_finalize();
		return 1;
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

	
	//std::unordered_map<std::string, std::string> stackLevelMonitoredFunctions; --> To remove
	
	std::unordered_map<BYTE*, SIZE_T>& dllPatterns;
	std::unordered_map<BYTE*, SIZE_T>& generalPatterns;
	std::unordered_map<int, BYTE*> *stackPatterns;
	std::unordered_map<BYTE*, SIZE_T> heapPatterns;


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

	NtSuspendProcess pfnNtSuspendProcess;
	NtResumeProcess pfnNtResumeProcess;

public:

	void setPatterns(
		std::unordered_map<BYTE*, SIZE_T>& dll_p,
		std::unordered_map<BYTE*, SIZE_T>& general_p,
		std::unordered_map<int, BYTE*> *stack_p,
		std::unordered_map<BYTE*, SIZE_T> heapPatterns
	) {
		this->dllPatterns = dll_p;
		this->generalPatterns = general_p;
		this->stackPatterns = stack_p;
		this->heapPatterns = heapPatterns;

		std::cout << "[DEBUG] stackPatterns : " << stackPatterns->size() << std::endl;
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
		directSyscallEnabled(dsyscalls) {

		pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtSuspendProcess");
		pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeProcess");

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
						
						//if (_v_) { // [JSON] ?
						//	std::cout << "\n" << root.toStyledString() << std::endl;
						//}
						//

						if (root.isMember("RSP")) {

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

						}
						
						if (root.isMember("RIP") 
							&& root["RIP"].asString() != "00007FFA71EEC5F4"
							&& root["RIP"].asString() != "00007FFA71EEACF4"	
							&& root["RIP"].asString() != "00007FF83EE4ACF4"
							&& root["RIP"].asString() != "00007FF83EE4C5F4"
							&& root["RIP"].asString() != "00007FF83EE4A034") {
							
							std::string ripPointer = root["RIP"].asString();
						
							stackEnabled = _stack_val_global_;

							if (stackEnabled) {
								analyzeCompleteProcessThreadsStackTrace(targetProcess);
							}

							if (_v_) {
								std::cout << "\n[*] RIP is at 0x" << ripPointer;
							}

							DWORD_PTR targetAddress = std::stoull(ripPointer, nullptr, 16);

							SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
							SymInitialize(targetProcess, NULL, TRUE);

							if (SymFromAddr(targetProcess, (DWORD_PTR&)targetAddress, &displacement, &symbolInfo)) {
								if (symbolInfo.Name != NULL) {

									if (_v_) { std::cout << "\t -> " << symbolInfo.Name << std::endl;  }

								}
							} else {

								if (directSyscallEnabled) {

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
								}
							}
						}

						if (root.isMember("Thread")) {
							std::cout << "Thread Created" << std::endl;
						}

						if (root.isMember("Function")) {

									pfnNtSuspendProcess(targetProcess);

									//if (heapEnabled) {
									heapUtils.retrieveHeapRegions();
										//heapUtils.printAllHeapRegionsContent();
										for (int i = 0; i < heapUtils.getHeapCount(); i++) {
											BYTE* data = heapUtils.getHeapRegionContent(i);
											yr_scanner_scan_mem(scanner, data, heapUtils.getHeapRegionSize(i));
										}
									//}
									
								/*	for (auto& thread : *hThreads) {
										SuspendThread(thread);
									}*/
							
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
											//addr = LPVOIDToBYTE((LPVOID)addrPointer);
										}
									}

									/////TODO : debug
									//if (_v_) {
									//	std::string jsonDump(jsonString);
									//	std::cout << jsonDump << "\n" << std::endl;
									///*	printf("Received address: 0x%02X%02X%02X%02X%02X%02X%02X%02X\n",
									//		rAddr[0], rAddr[1], rAddr[2], rAddr[3], rAddr[4], rAddr[5], rAddr[6], rAddr[7]);*/
									//}

									BYTE dump[1024];
									size_t dumpBytesRead;

									if (ReadProcessMemory(targetProcess, (LPCVOID)addrPointer, dump, sizeof(dump), &dumpBytesRead)) {

										if (yaraEnabled) {
											if(yr_scanner_scan_mem(scanner, dump, dumpBytesRead) == CALLBACK_ERROR) {
												alertAndKillThatProcess(targetProcess);
												deleteMonitoringFunc();
												startupFunc();
											}
										}
										else {

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
	
									pfnNtResumeProcess(targetProcess);
									/*for (auto& thread : *hThreads) {
										ResumeThread(thread);
									}*/
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

									IMAGEHLP_SYMBOL64* symbol = (IMAGEHLP_SYMBOL64*)malloc(sizeof(IMAGEHLP_SYMBOL64) + 1024);
									symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
									symbol->MaxNameLength = 1024;

									yaraEnabled = _yara_enabled_global_;

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
													// TODO --> écrasement de la valeur de yaraEnabled !!
													if (yaraEnabled) {
														yr_scanner_scan_mem(scanner, paramValue, bytesRead);
													} else {
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
																	(DWORD_PTR)stackFrame64.AddrPC.Offset	
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
												printOrangeAlert("Scanning the process (Yara)...");
												yr_scanner_scan_proc(scanner, GetProcessId(hProcess));
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







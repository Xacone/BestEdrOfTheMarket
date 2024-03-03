#pragma once

#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <iostream>
#include <vector>
#include <json/json.h> 
#include <string>

#include "ErrorsReportingUtils.h"
#include "ColorsUtils.h"
#include "BytesSequencesUtils.h"
#include "ReportingUtils.h"

#define PIPE_BUFFER_SIZE 512

typedef void (*DeleteMonitoringWorkerThreads)();
typedef void (*Startup)();

class IpcUtils {

private: 

	//static std::vector<HANDLE> pipes;

	HANDLE hPipe;
	HANDLE targetProcess;
	BYTE buffer[1024];
	DWORD bytesRead;
	LPCWSTR pipeName;
	BOOL _v_;
	std::unordered_map<BYTE*, SIZE_T> &dllPatterns;
	std::unordered_map<BYTE*, SIZE_T> &generalPatterns;

	DeleteMonitoringWorkerThreads deleteMonitoringFunc;
	Startup startupFunc;

	Pe64Utils *pe64Utils;
	std::unordered_map<std::string, DWORD_PTR>* functionsNamesMapping; // useless ?

	SYMBOL_INFO symbolInfo;
	DWORD64 displacement;

	std::vector<HANDLE>* hThreads;

public:

	IpcUtils(LPCWSTR pipeName,
		HANDLE& tProcess,
		BOOL& verbose,
		std::unordered_map<BYTE*, SIZE_T>& dllPatterns,
		std::unordered_map<BYTE*, SIZE_T>& generalPatterns,
		DeleteMonitoringWorkerThreads f1,
		Startup f2,
		Pe64Utils* pe64utils) :

		pipeName(pipeName),
		targetProcess(tProcess),
		_v_(verbose),
		dllPatterns(dllPatterns),
		generalPatterns(generalPatterns),
		deleteMonitoringFunc(f1),
		startupFunc(f2),
		pe64Utils(pe64utils)
	{
		functionsNamesMapping = pe64Utils->getFunctionsNamesMapping();
		//hThreads = pe64Utils->getThreads();
	}

	void alertAndKillThatProcess(HANDLE hProc) {

		HWND hWndParent = NULL;

		TerminateProcess(hProc, -1);
		CloseHandle(hPipe);
		int msgbox = MessageBoxA(NULL, "Malicious process detected (DLL) !", "BestEdrOfTheMarket", MB_ICONEXCLAMATION);
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
						
						if (_v_) {
							std::cout << "[JSON]\n" << root.toStyledString() << std::endl;
						}
						
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
									std::string("Direct Syscall detection through callbacks interceptions"),
									rspPointer
								);

								std::cout << "\n" << report << "\n" << std::endl;

								alertAndKillThatProcess(targetProcess);
								deleteMonitoringFunc();
								startupFunc();
							}

						}
						
						if (root.isMember("RIP")) {
							
							std::string ripPointer = root["RIP"].asString();
							
							if (_v_) {
								std::cout << "RIP @ " << ripPointer << std::endl;
							}

							DWORD_PTR targetAddress = std::stoull(ripPointer, nullptr, 16);

							SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
							SymInitialize(targetProcess, NULL, TRUE);

							if (SymFromAddr(targetProcess, (DWORD_PTR&)targetAddress, &displacement, &symbolInfo)) {
								if (symbolInfo.Name != NULL) {
									if (_v_) { std::cout << "\t[*]" << symbolInfo.Name << std::endl;  }
								}
							} else {


								std::cout << "\n";
								std::string alertText = "Direct Syscall stub at " + ripPointer ;
								printRedAlert(alertText);
								
								std::string report = directSyscallReportingJson(
									GetProcessId(targetProcess),
									std::string(GetProcessPathByPID((DWORD)GetProcessId(targetProcess), targetProcess)),
									std::string("Direct Syscall detection through callbacks interceptions"),
									ripPointer
								);

								std::cout << "\n" << report << "\n" << std::endl;

								alertAndKillThatProcess(targetProcess);
								deleteMonitoringFunc();
								startupFunc();
							
							}
						}

						if (root.isMember("Function")) {
							
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

									///TODO : debug
									if (_v_) {
										std::string jsonDump(jsonString);
										std::cout << jsonDump << "\n" << std::endl;
									/*	printf("Received address: 0x%02X%02X%02X%02X%02X%02X%02X%02X\n",
											rAddr[0], rAddr[1], rAddr[2], rAddr[3], rAddr[4], rAddr[5], rAddr[6], rAddr[7]);*/
									}

									BYTE dump[1024];
									size_t dumpBytesRead;

									if (ReadProcessMemory(targetProcess, (LPCVOID)addrPointer, dump, sizeof(dump), &dumpBytesRead)) {

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
};







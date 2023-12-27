#pragma once

#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <iostream>
#include <vector>
#include <json/json.h> 

#include "ErrorsReportingUtils.h"
#include "ColorsUtils.h"
#include "BytesSequencesUtils.h"

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

public:

	IpcUtils(LPCWSTR pipeName,
		HANDLE& tProcess,
		BOOL& verbose,
		std::unordered_map<BYTE*, SIZE_T>& dllPatterns,
		std::unordered_map<BYTE*, SIZE_T>& generalPatterns,
		DeleteMonitoringWorkerThreads f1,
		Startup f2) :

		pipeName(pipeName),
		targetProcess(tProcess),
		_v_(verbose),
		dllPatterns(dllPatterns),
		generalPatterns(generalPatterns),
		deleteMonitoringFunc(f1),
		startupFunc(f2)

	{}

	void alertAndKillThatProcess(HANDLE hProc) {
		CloseHandle(hPipe);
		MessageBoxA(NULL, "Malicious process detected (DLL) ! Terminating it...", "BestEdrOfTheMarket", MB_ICONEXCLAMATION);
		printRedAlert("Malicious process detected! Terminating it...");
		TerminateProcess(hProc, -1);
	}

	HANDLE initPipeAndWaitForConnection() {

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
						
						std::string routineName = root["Function"].asString();
						
						printBlueAlert("Intercepted " + routineName);	

						size_t capturedDataSize = (size_t)strlen(root["Data"].asCString());
						BYTE* addr = hexStringToBytes(root["Data"].asCString(), capturedDataSize);

						//BYTE sAddr[8] = { addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7] };
						BYTE rAddr[8] = { addr[7], addr[6], addr[5], addr[4], addr[3], addr[2], addr[1], addr[0] };

						LPCVOID addrPointer;
						memccpy(&addrPointer, addr, 8, 8);

						BYTE dump[1024];
						size_t dumpBytesRead;

						///TODO : debug
						if (_v_) {
							std::string jsonDump(jsonString);
							std::cout << jsonDump << "\n" << std::endl;
							printf("Received address: 0x%02X%02X%02X%02X%02X%02X%02X%02X\n",
								rAddr[0], rAddr[1], rAddr[2], rAddr[3], rAddr[4], rAddr[5], rAddr[6], rAddr[7]);

							printByteArray(dump, dumpBytesRead);
						}

						if (ReadProcessMemory(targetProcess, (LPCVOID)addrPointer, dump, sizeof(dump), &dumpBytesRead)) {
							
							for (const auto& pair : dllPatterns) {
								if (containsSequence(dump, dumpBytesRead, pair.first, pair.second)) {
									alertAndKillThatProcess(targetProcess);
									deleteMonitoringFunc();
									startupFunc();
								}
							}

							/*
							for (const auto& pair : generalPatterns) {
								if (containsSequence(dump, dumpBytesRead, pair.first, pair.second)) {
									alertAndKillThatProcess(targetProcess);
									deleteMonitoringFunc();
									startupFunc();
								}
							}*/
							
						}

						


						//DWORD_PTR dwordPtrValue = *reinterpret_cast<DWORD_PTR*>(rAddr);
						//LPVOID lpvoidValue = reinterpret_cast<LPVOID>(dwor dPtrValue);

						//std::cout << std::hex << (DWORD_PTR)dwordPtrValue << std::endl;
						//std::cout << std::hex << (LPVOID)dwordPtrValue << std::endl;

						/*
						BYTE dump[2048];
						size_t dumpBytesRead;

						reverseBytesOrder(addr, capturedDataSize);

						if (ReadProcessMemory(targetProcess, pVoidPointer, dump, sizeof(dump), &dumpBytesRead)) {
							printByteArray(dump, dumpBytesRead);
						} else {
							std::cout << "bah non chef " << std::endl;
						}
						*/


						

						/*
						for (const auto& pair : dllPatterns) {
							if (containsSequence(hexDump, bytesRead, pair.first, pair.second)) {
								alertAndKillThatProcess(targetProcess);
									deleteMonitoringFunc();
									startupFunc();
							}
						}

						for (const auto& pair : generalPatterns) {
							if (containsSequence(hexDump, bytesRead, pair.first, pair.second)) {
								alertAndKillThatProcess(targetProcess);
								deleteMonitoringFunc();
								startupFunc();
							}
						}
						*/
						
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






